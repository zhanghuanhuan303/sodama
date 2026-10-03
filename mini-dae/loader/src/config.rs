// SPDX-License-Identifier: GPL-2.0
//! dae `.dae` 配置的全量解析（K3）。
//!
//! 对照 dae：
//! - `pkg/config_parser` 的 AST（Section/Item/Param/Function/RoutingRule）与 ANTLR 词法
//!   （`dae_config.tokens`：`,` `{` `}` `:` `[` `]` `!` `(` `)` `->` `&&`，注释 `#` 与 `/* */`）；
//! - `config/config_merger.go`：include 展开（仅 `.dae`、必须在入口文件目录下、
//!   权限不得过宽（`mode & 0o037 == 0`）、同一文件重复包含即报循环）、glob、父在前子在后；
//! - `config/config.go` + `config/parser.go`：schema 校验（未知 section/key 报错、
//!   `global` 与 `routing` 必填、每个 group 的 `policy` 必填、
//!   `dns.routing.{request,response}.fallback` 必填）。
//!
//! 本模块只做「解析 + 校验 + 导出」；把路由段编译成 mini-dae 数据面语法的子集见
//! [`extract_routing`]：不能编译的规则显式进入 `deferred` 列表，绝不静默丢弃。

use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::fmt::Write as _;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------- AST

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Loc {
    /// cfg.files 的下标
    pub file: usize,
    pub line: usize,
}

impl fmt::Display for Loc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}", self.line)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Function {
    pub name: String,
    pub not: bool,
    pub params: Vec<Param>,
    pub loc: Loc,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Param {
    /// None = 无 key 参数（dae AST 里 `Key == ""`）
    pub key: Option<String>,
    /// 字符串值（与 funcs 互斥）
    pub val: Option<String>,
    /// `key: f1(...) && f2(...)` 的函数列表
    pub funcs: Option<Vec<Function>>,
    /// `[add_latency: -500ms]` 注解
    pub annotation: Vec<Param>,
    pub loc: Option<Loc>,
}

impl Param {
    pub fn display(&self) -> String {
        let mut s = String::new();
        if let Some(k) = &self.key {
            let _ = write!(s, "{k}: ");
        }
        if let Some(fs) = &self.funcs {
            let parts: Vec<String> = fs.iter().map(Function::display).collect();
            let _ = write!(s, "{}", parts.join(" && "));
        } else if let Some(v) = &self.val {
            let _ = write!(s, "{v}");
        }
        if !self.annotation.is_empty() {
            let parts: Vec<String> = self.annotation.iter().map(Param::display).collect();
            let _ = write!(s, " [{}]", parts.join(", "));
        }
        s
    }
}

impl Function {
    pub fn display(&self) -> String {
        let mut s = String::new();
        if self.not {
            s.push('!');
        }
        s.push_str(&self.name);
        if !self.params.is_empty() {
            s.push('(');
            let parts: Vec<String> = self.params.iter().map(Param::display).collect();
            s.push_str(&parts.join(", "));
            s.push(')');
        }
        s
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub and_functions: Vec<Function>,
    pub outbound: Function,
    pub loc: Loc,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Item {
    Param(Param),
    Section(Section),
    Rule(Rule),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    pub name: String,
    pub items: Vec<Item>,
    pub loc: Loc,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub entry: PathBuf,
    /// 参与合并的全部文件（按加载顺序去重）
    pub files: Vec<PathBuf>,
    pub sections: Vec<Section>,
}

/// P14：读取 global 段的字符串参数（运行时开关，如 `dial_mode`）。
pub fn global_value(cfg: &Config, key: &str) -> Option<String> {
    for sec in &cfg.sections {
        if sec.name != "global" {
            continue;
        }
        for item in &sec.items {
            if let Item::Param(p) = item {
                if p.key.as_deref() == Some(key) {
                    return p.val.clone();
                }
            }
        }
    }
    None
}

#[derive(Debug, Clone)]
pub struct Diag {
    pub file: Option<PathBuf>,
    pub line: usize,
    pub msg: String,
}

impl fmt::Display for Diag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.file {
            Some(p) => write!(f, "{}:{}: {}", p.display(), self.line, self.msg),
            None => write!(f, "{}", self.msg),
        }
    }
}

fn diag(file: Option<&Path>, line: usize, msg: impl Into<String>) -> Diag {
    Diag {
        file: file.map(Path::to_path_buf),
        line,
        msg: msg.into(),
    }
}

// ---------------------------------------------------------------- 词法

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    LBrace,
    RBrace,
    LParen,
    RParen,
    LBracket,
    RBracket,
    Colon,
    Comma,
    Bang,
    Arrow,
    AndAnd,
    Word(String),
    Quoted(String),
}

impl Tok {
    fn describe(&self) -> String {
        match self {
            Tok::LBrace => "'{'".into(),
            Tok::RBrace => "'}'".into(),
            Tok::LParen => "'('".into(),
            Tok::RParen => "')'".into(),
            Tok::LBracket => "'['".into(),
            Tok::RBracket => "']'".into(),
            Tok::Colon => "':'".into(),
            Tok::Comma => "','".into(),
            Tok::Bang => "'!'".into(),
            Tok::Arrow => "'->'".into(),
            Tok::AndAnd => "'&&'".into(),
            Tok::Word(w) => format!("'{w}'"),
            Tok::Quoted(q) => format!("'{q}'"),
        }
    }
}

#[derive(Debug, Clone)]
struct Token {
    tok: Tok,
    line: usize,
}

/// 裸词（ID / NON_ID 合并）允许的字符：除空白、注释引导符与结构符号外都可。
fn is_bare_char(c: char) -> bool {
    !c.is_whitespace()
        && !matches!(
            c,
            '{' | '}' | '(' | ')' | '[' | ']' | ':' | ',' | '"' | '\'' | '#' | '!' | '&'
        )
}

fn lex(src: &str, file: &Path) -> Result<Vec<Token>, Vec<Diag>> {
    let chars: Vec<char> = src.chars().collect();
    let mut out = Vec::new();
    let mut i = 0usize;
    let mut line = 1usize;
    while i < chars.len() {
        let c = chars[i];
        match c {
            '\n' => {
                line += 1;
                i += 1;
            }
            c if c.is_whitespace() => i += 1,
            '#' => {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
            }
            '/' if i + 1 < chars.len() && chars[i + 1] == '*' => {
                let start_line = line;
                i += 2;
                loop {
                    if i + 1 >= chars.len() {
                        return Err(vec![diag(Some(file), start_line, "未闭合的块注释 '/*'")]);
                    }
                    if chars[i] == '*' && chars[i + 1] == '/' {
                        i += 2;
                        break;
                    }
                    if chars[i] == '\n' {
                        line += 1;
                    }
                    i += 1;
                }
            }
            '{' => {
                out.push(Token {
                    tok: Tok::LBrace,
                    line,
                });
                i += 1;
            }
            '}' => {
                out.push(Token {
                    tok: Tok::RBrace,
                    line,
                });
                i += 1;
            }
            '(' => {
                out.push(Token {
                    tok: Tok::LParen,
                    line,
                });
                i += 1;
            }
            ')' => {
                out.push(Token {
                    tok: Tok::RParen,
                    line,
                });
                i += 1;
            }
            '[' => {
                out.push(Token {
                    tok: Tok::LBracket,
                    line,
                });
                i += 1;
            }
            ']' => {
                out.push(Token {
                    tok: Tok::RBracket,
                    line,
                });
                i += 1;
            }
            ':' => {
                out.push(Token {
                    tok: Tok::Colon,
                    line,
                });
                i += 1;
            }
            ',' => {
                out.push(Token {
                    tok: Tok::Comma,
                    line,
                });
                i += 1;
            }
            '!' => {
                // `!` 只在 token 起始位置是取反运算符；词内出现（如 geosite 的
                // `geolocation-!cn`、`cn@!ads`）并入上一个 Word（对照 dae：值里的
                // `!` 是普通字符）。
                let after_bare = i > 0 && is_bare_char(chars[i - 1]);
                if after_bare {
                    let start = i;
                    i += 1;
                    while i < chars.len() && is_bare_char(chars[i]) {
                        i += 1;
                    }
                    let tail: String = chars[start..i].iter().collect();
                    match out.last_mut() {
                        Some(Token {
                            tok: Tok::Word(prev),
                            ..
                        }) => prev.push_str(&tail),
                        _ => out.push(Token {
                            tok: Tok::Word(tail),
                            line,
                        }),
                    }
                } else {
                    out.push(Token {
                        tok: Tok::Bang,
                        line,
                    });
                    i += 1;
                }
            }
            '-' if i + 1 < chars.len() && chars[i + 1] == '>' => {
                out.push(Token {
                    tok: Tok::Arrow,
                    line,
                });
                i += 2;
            }
            '&' if i + 1 < chars.len() && chars[i + 1] == '&' => {
                out.push(Token {
                    tok: Tok::AndAnd,
                    line,
                });
                i += 2;
            }
            '\'' | '"' => {
                let quote = c;
                let start_line = line;
                i += 1;
                let mut s = String::new();
                loop {
                    if i >= chars.len() || chars[i] == '\n' {
                        return Err(vec![diag(Some(file), start_line, "未闭合的引号字符串")]);
                    }
                    let ch = chars[i];
                    if ch == quote {
                        i += 1;
                        break;
                    }
                    if ch == '\\' && i + 1 < chars.len() {
                        i += 1;
                        let esc = chars[i];
                        match esc {
                            'n' => s.push('\n'),
                            't' => s.push('\t'),
                            'r' => s.push('\r'),
                            '\\' => s.push('\\'),
                            '\'' => s.push('\''),
                            '"' => s.push('"'),
                            other => s.push(other),
                        }
                        i += 1;
                        continue;
                    }
                    s.push(ch);
                    i += 1;
                }
                out.push(Token {
                    tok: Tok::Quoted(s),
                    line: start_line,
                });
            }
            c if is_bare_char(c) => {
                let start = i;
                while i < chars.len() && is_bare_char(chars[i]) {
                    i += 1;
                }
                out.push(Token {
                    tok: Tok::Word(chars[start..i].iter().collect()),
                    line,
                });
            }
            other => {
                return Err(vec![diag(
                    Some(file),
                    line,
                    format!("无法识别的字符 '{other}'"),
                )]);
            }
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------- 语法

struct Parser<'a> {
    toks: &'a [Token],
    pos: usize,
    file: &'a Path,
    file_idx: usize,
    errors: Vec<Diag>,
}

impl<'a> Parser<'a> {
    fn new(toks: &'a [Token], file: &'a Path, file_idx: usize) -> Self {
        Self {
            toks,
            pos: 0,
            file,
            file_idx,
            errors: Vec::new(),
        }
    }

    fn peek(&self) -> Option<&Token> {
        self.toks.get(self.pos)
    }

    fn bump(&mut self) -> Option<(Tok, usize)> {
        let t = self.toks.get(self.pos)?;
        let out = (t.tok.clone(), t.line);
        self.pos += 1;
        Some(out)
    }

    fn line(&self) -> usize {
        self.peek()
            .map(|t| t.line)
            .unwrap_or_else(|| self.toks.last().map(|t| t.line).unwrap_or(1))
    }

    fn err(&mut self, msg: impl Into<String>) {
        let line = self.line();
        self.errors.push(diag(Some(self.file), line, msg));
    }

    fn expect(&mut self, want: Tok) -> bool {
        match self.peek() {
            Some(t) if t.tok == want => {
                self.pos += 1;
                true
            }
            Some(t) => {
                let (line, got) = (t.line, t.tok.describe());
                self.errors.push(diag(
                    Some(self.file),
                    line,
                    format!("期望 {}，得到 {got}", want.describe()),
                ));
                false
            }
            None => {
                self.err(format!("期望 {}，但输入已结束", want.describe()));
                false
            }
        }
    }

    fn loc_at(&self, line: usize) -> Loc {
        Loc {
            file: self.file_idx,
            line,
        }
    }

    /// document := section*
    fn parse_document(&mut self) -> Vec<Section> {
        let mut out = Vec::new();
        while self.peek().is_some() {
            if let Some(sec) = self.parse_section() {
                out.push(sec);
            } else {
                // 避免死循环：跳过一个 token
                self.pos += 1;
            }
        }
        out
    }

    /// section := (Word|Quoted) '{' item* '}'
    fn parse_section(&mut self) -> Option<Section> {
        let (name, line) = match self.bump() {
            Some((Tok::Word(w), l)) => (w, l),
            Some((Tok::Quoted(q), l)) => (q, l),
            Some((t, l)) => {
                let d = t.describe();
                self.errors.push(diag(
                    Some(self.file),
                    l,
                    format!("顶层只允许 section，得到 {d}"),
                ));
                return None;
            }
            None => return None,
        };
        if !matches!(self.peek().map(|t| &t.tok), Some(Tok::LBrace)) {
            self.err(format!("section '{name}' 后应为 '{{'"));
            return None;
        }
        self.pos += 1;
        let mut items = Vec::new();
        loop {
            match self.peek().map(|t| t.tok.clone()) {
                Some(Tok::RBrace) => {
                    self.pos += 1;
                    break;
                }
                None => {
                    self.err(format!("section '{name}' 缺少 '}}'"));
                    break;
                }
                _ => {
                    if let Some(item) = self.parse_item() {
                        items.push(item);
                    } else {
                        self.pos += 1;
                    }
                }
            }
        }
        Some(Section {
            name,
            items,
            loc: self.loc_at(line),
        })
    }

    /// item := rule | keyed_param | bare_param | subsection
    fn parse_item(&mut self) -> Option<Item> {
        match self.peek().map(|t| t.tok.clone()) {
            Some(Tok::Bang) => self.parse_rule().map(Item::Rule),
            Some(Tok::Word(_)) | Some(Tok::Quoted(_)) => {
                // Word/Quoted + '(' → 规则；+ ':' → 带 key 参数；+ '{' → 子 section；否则裸参数
                let is_func = matches!(
                    self.toks.get(self.pos + 1).map(|t| &t.tok),
                    Some(Tok::LParen)
                );
                let is_key = matches!(
                    self.toks.get(self.pos + 1).map(|t| &t.tok),
                    Some(Tok::Colon)
                );
                let is_sub = matches!(
                    self.toks.get(self.pos + 1).map(|t| &t.tok),
                    Some(Tok::LBrace)
                );
                if is_func {
                    self.parse_rule().map(Item::Rule)
                } else if is_key {
                    self.parse_keyed_param().map(Item::Param)
                } else if is_sub {
                    self.parse_section().map(Item::Section)
                } else {
                    let (tok, tl) = self.bump()?;
                    let val = match tok {
                        Tok::Word(w) => w,
                        Tok::Quoted(q) => q,
                        _ => {
                            self.err("裸参数应为标识或引号字符串");
                            return None;
                        }
                    };
                    Some(Item::Param(Param {
                        key: None,
                        val: Some(val),
                        funcs: None,
                        annotation: Vec::new(),
                        loc: Some(self.loc_at(tl)),
                    }))
                }
            }
            _ => {
                self.err("无法解析的条目");
                None
            }
        }
    }

    /// keyed_param := (Word|Quoted) ':' value_expr annotation?
    fn parse_keyed_param(&mut self) -> Option<Param> {
        let (tok, line) = self.bump()?;
        let key = match tok {
            Tok::Word(w) => w,
            Tok::Quoted(q) => q,
            _ => {
                self.err("参数名应为标识或引号字符串");
                return None;
            }
        };
        self.expect(Tok::Colon);
        let mut p = self.parse_value_expr(self.loc_at(line))?;
        p.key = Some(key);
        // P17a：允许 `ext:file:code` 这类多段冒号值（仅对非函数、非引号的值生效）。
        // dae 语法里有 `dip(ext:geoip.dat:cn)`，其值不是 URL，不会与引号写法冲突。
        if p.funcs.is_none() {
            if let Some(v) = p.val.as_mut() {
                while matches!(self.peek().map(|t| &t.tok), Some(Tok::Colon)) {
                    self.pos += 1;
                    let Some((tok, tl)) = self.bump() else { break };
                    let seg = match tok {
                        Tok::Word(w) => w,
                        Tok::Quoted(q) => q,
                        other => {
                            let d = other.describe();
                            self.errors.push(diag(
                                Some(self.file),
                                tl,
                                format!("ext 值段应为标识/引号字符串，得到 {d}"),
                            ));
                            break;
                        }
                    };
                    v.push(':');
                    v.push_str(&seg);
                }
            }
        }
        // 注解
        if matches!(self.peek().map(|t| &t.tok), Some(Tok::LBracket)) {
            self.pos += 1;
            loop {
                if matches!(self.peek().map(|t| &t.tok), Some(Tok::RBracket)) {
                    self.pos += 1;
                    break;
                }
                match self.parse_keyed_param() {
                    Some(ap) => p.annotation.push(ap),
                    None => {
                        self.pos += 1;
                        if matches!(self.peek().map(|t| &t.tok), Some(Tok::Comma)) {
                            self.pos += 1;
                        }
                    }
                }
                if matches!(self.peek().map(|t| &t.tok), Some(Tok::Comma)) {
                    self.pos += 1;
                } else if matches!(self.peek().map(|t| &t.tok), Some(Tok::RBracket)) {
                    self.pos += 1;
                    break;
                } else if self.peek().is_none() {
                    self.err("注解除 '[' 缺少 ']'");
                    break;
                }
            }
        }
        Some(p)
    }

    /// value_expr := func_list | token
    fn parse_value_expr(&mut self, loc: Loc) -> Option<Param> {
        let starts_func = match self.peek().map(|t| &t.tok) {
            Some(Tok::Bang) => true,
            Some(Tok::Word(_)) | Some(Tok::Quoted(_)) => {
                matches!(
                    self.toks.get(self.pos + 1).map(|t| &t.tok),
                    Some(Tok::LParen)
                )
            }
            _ => false,
        };
        if starts_func {
            let mut funcs = vec![self.parse_function()?];
            while matches!(self.peek().map(|t| &t.tok), Some(Tok::AndAnd)) {
                self.pos += 1;
                funcs.push(self.parse_function()?);
            }
            return Some(Param {
                key: None,
                val: None,
                funcs: Some(funcs),
                annotation: Vec::new(),
                loc: Some(loc),
            });
        }
        let (tok, tl) = self.bump()?;
        let val = match tok {
            Tok::Word(w) => w,
            Tok::Quoted(q) => q,
            other => {
                let d = other.describe();
                self.errors.push(diag(
                    Some(self.file),
                    tl,
                    format!("参数值应为标识/引号字符串/函数，得到 {d}"),
                ));
                return None;
            }
        };
        Some(Param {
            key: None,
            val: Some(val),
            funcs: None,
            annotation: Vec::new(),
            loc: Some(self.loc_at(tl)),
        })
    }

    /// rule := func ('&&' func)* '->' func
    fn parse_rule(&mut self) -> Option<Rule> {
        let line = self.peek()?.line;
        let mut and_functions = vec![self.parse_function()?];
        while matches!(self.peek().map(|t| &t.tok), Some(Tok::AndAnd)) {
            self.pos += 1;
            and_functions.push(self.parse_function()?);
        }
        self.expect(Tok::Arrow);
        let outbound = self.parse_function()?;
        Some(Rule {
            and_functions,
            outbound,
            loc: self.loc_at(line),
        })
    }

    /// func := '!'? (Word|Quoted) ('(' params? ')')?
    fn parse_function(&mut self) -> Option<Function> {
        let not = if matches!(self.peek().map(|t| &t.tok), Some(Tok::Bang)) {
            self.pos += 1;
            true
        } else {
            false
        };
        let (tok, line) = self.bump()?;
        let name = match tok {
            Tok::Word(w) => w,
            Tok::Quoted(q) => q,
            other => {
                let d = other.describe();
                self.errors.push(diag(
                    Some(self.file),
                    line,
                    format!("函数名应为标识，得到 {d}"),
                ));
                return None;
            }
        };
        let mut params = Vec::new();
        if matches!(self.peek().map(|t| &t.tok), Some(Tok::LParen)) {
            self.pos += 1;
            loop {
                if matches!(self.peek().map(|t| &t.tok), Some(Tok::RParen)) {
                    self.pos += 1;
                    break;
                }
                // 参数：key: value / 裸值 / key: 函数列表
                let is_key = matches!(
                    self.toks.get(self.pos + 1).map(|t| &t.tok),
                    Some(Tok::Colon)
                );
                let p = if is_key {
                    self.parse_keyed_param()
                } else {
                    let l = self.peek()?.line;
                    self.parse_value_expr(self.loc_at(l))
                };
                match p {
                    Some(p) => params.push(p),
                    None => {
                        self.pos += 1;
                    }
                }
                if matches!(self.peek().map(|t| &t.tok), Some(Tok::Comma)) {
                    self.pos += 1;
                } else if matches!(self.peek().map(|t| &t.tok), Some(Tok::RParen)) {
                    self.pos += 1;
                    break;
                } else if self.peek().is_none() {
                    self.err("函数参数缺少 ')'");
                    break;
                }
            }
        }
        Some(Function {
            name,
            not,
            params,
            loc: self.loc_at(line),
        })
    }
}

/// 解析单个文件的文本为 sections（不含 include 展开）。
pub fn parse_text(src: &str, file: &Path, file_idx: usize) -> Result<Vec<Section>, Vec<Diag>> {
    let toks = lex(src, file)?;
    let mut p = Parser::new(&toks, file, file_idx);
    let sections = p.parse_document();
    if p.errors.is_empty() {
        Ok(sections)
    } else {
        Err(p.errors)
    }
}

// ---------------------------------------------------------------- include 合并

fn glob_match(pat: &str, name: &str) -> bool {
    // 支持 '*'（含空串）、'?' 与 '[...]'（简单字符类，`!`/`^` 取反）
    let p: Vec<char> = pat.chars().collect();
    let n: Vec<char> = name.chars().collect();
    fn rec(p: &[char], n: &[char]) -> bool {
        if p.is_empty() {
            return n.is_empty();
        }
        match p[0] {
            '*' => (0..=n.len()).any(|k| rec(&p[1..], &n[k..])),
            '?' => !n.is_empty() && rec(&p[1..], &n[1..]),
            '[' => {
                if n.is_empty() {
                    return false;
                }
                let mut i = 1;
                let mut negate = false;
                if i < p.len() && (p[i] == '!' || p[i] == '^') {
                    negate = true;
                    i += 1;
                }
                let mut matched = false;
                let mut prev: Option<char> = None;
                while i < p.len() && p[i] != ']' {
                    if p[i] == '-' && prev.is_some() && i + 1 < p.len() && p[i + 1] != ']' {
                        let lo = prev.unwrap();
                        let hi = p[i + 1];
                        if lo <= n[0] && n[0] <= hi {
                            matched = true;
                        }
                        prev = Some(hi);
                        i += 2;
                        continue;
                    }
                    if p[i] == n[0] {
                        matched = true;
                    }
                    prev = Some(p[i]);
                    i += 1;
                }
                if i >= p.len() {
                    return false; // 未闭合的 '['
                }
                if matched != negate {
                    rec(&p[i + 1..], &n[1..])
                } else {
                    false
                }
            }
            c => !n.is_empty() && n[0] == c && rec(&p[1..], &n[1..]),
        }
    }
    rec(&p, &n)
}

/// 展开一个 glob 模式（相对路径以 entry_dir 为基准），只保留 `*.dae` 文件，结果排序。
fn expand_glob(entry_dir: &Path, pattern: &str) -> Result<Vec<PathBuf>, String> {
    let joined = if Path::new(pattern).is_absolute() {
        PathBuf::from(pattern)
    } else {
        entry_dir.join(pattern)
    };
    let comps: Vec<String> = joined
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    let mut results = Vec::new();
    if comps.is_empty() {
        return Ok(results);
    }
    let start = if comps[0] == "/" {
        PathBuf::from("/")
    } else {
        PathBuf::from(&comps[0])
    };
    let rest = if comps[0] == "/" {
        &comps[1..]
    } else {
        &comps[1..]
    };

    fn walk(dir: &Path, rest: &[String], out: &mut Vec<PathBuf>) -> Result<(), String> {
        if rest.is_empty() {
            return Ok(());
        }
        let comp = &rest[0];
        let last = rest.len() == 1;
        if !comp.contains(['*', '?', '[']) {
            let next = dir.join(comp);
            if last {
                if next.is_file() {
                    out.push(next);
                }
            } else {
                walk(&next, &rest[1..], out)?;
            }
            return Ok(());
        }
        let mut entries: Vec<_> = fs::read_dir(dir)
            .map_err(|e| format!("read_dir {}: {e}", dir.display()))?
            .filter_map(|e| e.ok())
            .collect();
        entries.sort_by_key(|e| e.file_name());
        for ent in entries {
            let name = ent.file_name().to_string_lossy().into_owned();
            if !glob_match(comp, &name) {
                continue;
            }
            let path = ent.path();
            if last {
                if path.is_file() && name.ends_with(".dae") {
                    out.push(path);
                }
            } else if path.is_dir() {
                walk(&path, &rest[1..], out)?;
            }
        }
        Ok(())
    }

    walk(&start, rest, &mut results)?;
    results.retain(|p| p.extension().map(|e| e == "dae").unwrap_or(false));
    Ok(results)
}

fn check_dae_file(path: &Path, entry_dir: &Path) -> Result<(), String> {
    let name = path.to_string_lossy();
    if !name.ends_with(".dae") {
        return Err(format!("配置文件必须以 .dae 结尾：{name}"));
    }
    let canon = path
        .canonicalize()
        .map_err(|e| format!("读取 {name}: {e}"))?;
    let canon_dir = entry_dir
        .canonicalize()
        .map_err(|e| format!("读取入口目录 {}: {e}", entry_dir.display()))?;
    if !canon.starts_with(&canon_dir) {
        return Err(format!(
            "include 的文件必须在入口配置目录下：{} 不在 {} 内",
            canon.display(),
            canon_dir.display()
        ));
    }
    let meta = fs::metadata(&canon).map_err(|e| format!("stat {name}: {e}"))?;
    if meta.is_dir() {
        return Err(format!("不能 include 目录：{name}"));
    }
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o037 != 0 {
        return Err(format!(
            "权限 {mode:04o} 过于开放（{name}）：要求同组不可写、其他用户不可读；建议 0640 或 0600"
        ));
    }
    Ok(())
}

fn sections_to_map(sections: Vec<Section>) -> (Vec<String>, BTreeMap<String, Vec<Item>>) {
    let mut order: Vec<String> = Vec::new();
    let mut map: BTreeMap<String, Vec<Item>> = BTreeMap::new();
    for sec in sections {
        if !map.contains_key(&sec.name) {
            order.push(sec.name.clone());
        }
        map.entry(sec.name).or_default().extend(sec.items);
    }
    (order, map)
}

fn merge_map(
    order: &mut Vec<String>,
    into: &mut BTreeMap<String, Vec<Item>>,
    from: BTreeMap<String, Vec<Item>>,
) {
    for (name, mut items) in from {
        if !into.contains_key(&name) {
            order.push(name.clone());
        }
        into.entry(name).or_default().append(&mut items);
    }
}

struct Loader {
    entry_dir: PathBuf,
    files: Vec<PathBuf>,
    loaded: HashSet<PathBuf>,
}

impl Loader {
    fn load_file(
        &mut self,
        path: &Path,
        stack: &[PathBuf],
    ) -> Result<(Vec<String>, BTreeMap<String, Vec<Item>>), Vec<Diag>> {
        let canon = path
            .canonicalize()
            .map_err(|e| vec![diag(None, 0, format!("读取 {}: {e}", path.display()))])?;
        if self.loaded.contains(&canon) {
            let chain: Vec<String> = stack.iter().map(|p| p.display().to_string()).collect();
            return Err(vec![diag(
                None,
                0,
                format!(
                    "circular include is not allowed: {} -> {}（同一文件不可被重复包含）",
                    chain.join(" -> "),
                    canon.display()
                ),
            )]);
        }
        if let Err(e) = check_dae_file(&canon, &self.entry_dir) {
            return Err(vec![diag(None, 0, e)]);
        }
        let text = fs::read_to_string(&canon)
            .map_err(|e| vec![diag(Some(&canon), 0, format!("读取失败: {e}"))])?;
        let file_idx = self.files.len();
        self.files.push(canon.clone());
        self.loaded.insert(canon.clone());
        let sections = parse_text(&text, &canon, file_idx)?;
        let (mut order, mut map) = sections_to_map(sections);

        // 展开 include：父在前，子在后（对照 dae config_merger.go dfsMerge）
        let includes: Vec<Param> = map
            .get("include")
            .map(|items| {
                items
                    .iter()
                    .filter_map(|it| match it {
                        Item::Param(p) => Some(p.clone()),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default();
        let mut next_stack = stack.to_vec();
        next_stack.push(canon.clone());
        for inc in includes {
            let Some(pattern) = inc.val.clone() else {
                return Err(vec![diag(
                    inc.loc.as_ref().map(|_| canon.as_path()),
                    inc.loc.as_ref().map(|l| l.line).unwrap_or(0),
                    "include 只接受路径字符串",
                )]);
            };
            let files = expand_glob(&self.entry_dir, &pattern)
                .map_err(|e| vec![diag(Some(&canon), 0, e)])?;
            for f in files {
                let (cord, cmap) = self.load_file(&f, &next_stack)?;
                merge_map(&mut order, &mut map, cmap);
                // 子文件里第一次出现的 section 也进入顺序表
                for name in cord {
                    if !order.contains(&name) {
                        order.push(name);
                    }
                }
            }
        }
        Ok((order, map))
    }
}

/// 加载入口配置：include 展开 + 合并（不校验 schema，见 [`validate`]）。
pub fn load(entry: &Path) -> Result<Config, Vec<Diag>> {
    let entry_dir = entry
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let mut loader = Loader {
        entry_dir,
        files: Vec::new(),
        loaded: HashSet::new(),
    };
    let (order, map) = loader.load_file(entry, &[])?;
    let entry_canon = entry
        .canonicalize()
        .map_err(|e| vec![diag(None, 0, format!("读取 {}: {e}", entry.display()))])?;
    let mut sections = Vec::new();
    for name in order {
        if let Some(items) = map.get(&name) {
            sections.push(Section {
                name,
                items: items.clone(),
                loc: Loc { file: 0, line: 1 },
            });
        }
    }
    Ok(Config {
        entry: entry_canon,
        files: loader.files,
        sections,
    })
}

// ---------------------------------------------------------------- schema 校验

const GLOBAL_KEYS: &[&str] = &[
    "tproxy_port",
    "tproxy_port_protect",
    "so_mark_from_dae",
    "log_level",
    "tcp_check_url",
    "tcp_check_http_method",
    "udp_check_dns",
    "check_interval",
    "check_tolerance",
    "lan_interface",
    "wan_interface",
    "allow_insecure",
    "dial_mode",
    "disable_waiting_network",
    "disable_thp",
    "enable_local_tcp_fast_redirect",
    "auto_config_kernel_parameter",
    "auto_config_firewall_rule",
    "sniffing_timeout",
    "auto_sniff_punt",
    "tls_implementation",
    "utls_imitate",
    "tls_fragment",
    "tls_fragment_length",
    "tls_fragment_interval",
    "pprof_port",
    "mptcp",
    "bootstrap_resolver",
    "fallback_resolver",
    "bandwidth_max_tx",
    "bandwidth_max_rx",
    "udphop_interval",
    "bpf_conn_state_map_size",
];

const DNS_KEYS: &[&str] = &[
    "ipversion_prefer",
    "fixed_domain_ttl",
    "upstream",
    "routing",
    "bind",
    "optimistic_cache",
    "optimistic_cache_ttl",
    "optimistic_stale_reply_ttl",
    "max_cache_size",
];

const GROUP_KEYS: &[&str] = &[
    "filter",
    "policy",
    "tcp_check_url",
    "tcp_check_http_method",
    "udp_check_dns",
    "check_interval",
    "check_tolerance",
];

const KNOWN_SECTIONS: &[&str] = &[
    "include",
    "global",
    "subscription",
    "node",
    "group",
    "routing",
    "dns",
];

fn p_loc(cfg: &Config, p: &Param) -> Diag {
    let line = p.loc.as_ref().map(|l| l.line).unwrap_or(0);
    let file = p.loc.as_ref().map(|l| cfg.files[l.file].clone());
    diag(file.as_deref(), line, String::new())
}

fn err_at(cfg: &Config, loc: &Loc, msg: impl Into<String>) -> Diag {
    diag(cfg.files.get(loc.file).map(PathBuf::as_path), loc.line, msg)
}

fn param_key_required(cfg: &Config, p: &Param, section: &str, out: &mut Vec<Diag>) {
    let Some(key) = &p.key else {
        let mut d = p_loc(cfg, p);
        d.msg = format!("section \"{section}\" 不支持无 key 的文本：{}", p.display());
        out.push(d);
        return;
    };
    if !key_allowed(section, key) {
        let mut d = p_loc(cfg, p);
        d.msg = format!("unexpected key: {key}（section \"{section}\"）");
        out.push(d);
    }
}

fn key_allowed(section: &str, key: &str) -> bool {
    match section {
        "global" => GLOBAL_KEYS.contains(&key),
        "dns" => DNS_KEYS.contains(&key),
        "group" => GROUP_KEYS.contains(&key),
        _ => true,
    }
}

/// schema 校验：对照 dae `config/config.go` 的 mapstructure 标签与
/// `config/parser.go` 的 ParamParser（未知键报错、必填检查）。
/// 返回按文件/行号排序的诊断；空 = 通过。
pub fn validate(cfg: &Config) -> Vec<Diag> {
    let mut out = Vec::new();
    let mut seen: HashSet<&str> = HashSet::new();
    for sec in &cfg.sections {
        if !KNOWN_SECTIONS.contains(&sec.name.as_str()) {
            out.push(err_at(
                cfg,
                &sec.loc,
                format!("unknown section: {}", sec.name),
            ));
            continue;
        }
        seen.insert(sec.name.as_str());
        match sec.name.as_str() {
            "include" => {
                for item in &sec.items {
                    match item {
                        Item::Param(p) if p.val.is_some() => {}
                        other => out.push(err_at(
                            cfg,
                            &sec.loc,
                            format!("include 只接受路径字符串：{other:?}"),
                        )),
                    }
                }
            }
            "global" => {
                for item in &sec.items {
                    match item {
                        Item::Param(p) => param_key_required(cfg, p, "global", &mut out),
                        Item::Section(s) => out.push(err_at(
                            cfg,
                            &s.loc,
                            format!("global 不支持子 section：{}", s.name),
                        )),
                        Item::Rule(r) => out.push(err_at(cfg, &r.loc, "global 不支持路由规则")),
                    }
                }
            }
            "routing" => {
                for item in &sec.items {
                    match item {
                        Item::Rule(_) => {}
                        Item::Param(p) => match p.key.as_deref() {
                            Some("fallback") => {}
                            Some(other) => {
                                let mut d = p_loc(cfg, p);
                                d.msg = format!(
                                    "unexpected key: {other}（routing 只支持 fallback 与规则）"
                                );
                                out.push(d);
                            }
                            None => {
                                let mut d = p_loc(cfg, p);
                                d.msg = "routing 中的裸文本不是合法规则".to_string();
                                out.push(d);
                            }
                        },
                        Item::Section(s) => out.push(err_at(
                            cfg,
                            &s.loc,
                            format!("routing 不支持子 section：{}", s.name),
                        )),
                    }
                }
            }
            "dns" => validate_dns(cfg, sec, &mut out),
            "group" => validate_groups(cfg, sec, &mut out),
            "node" | "subscription" => {
                for item in &sec.items {
                    match item {
                        Item::Param(p) => {
                            if p.funcs.is_some() {
                                let mut d = p_loc(cfg, p);
                                d.msg = format!("{} 只接受字符串值", sec.name);
                                out.push(d);
                            }
                        }
                        Item::Section(s) => out.push(err_at(
                            cfg,
                            &s.loc,
                            format!("{} 不支持子 section：{}", sec.name, s.name),
                        )),
                        Item::Rule(r) => {
                            out.push(err_at(cfg, &r.loc, format!("{} 不支持规则", sec.name)))
                        }
                    }
                }
            }
            _ => {}
        }
    }
    for required in ["global", "routing"] {
        if !seen.contains(required) {
            out.push(diag(
                None,
                0,
                format!("section {required} is required but not provided"),
            ));
        }
    }
    out.sort_by_key(|d| {
        (
            d.file.as_ref().map(|p| p.display().to_string()),
            d.line,
            d.msg.clone(),
        )
    });
    out
}

fn validate_dns(cfg: &Config, sec: &Section, out: &mut Vec<Diag>) {
    for item in &sec.items {
        match item {
            Item::Param(p) => param_key_required(cfg, p, "dns", out),
            Item::Rule(r) => out.push(err_at(
                cfg,
                &r.loc,
                "dns 顶层不支持规则（规则在 dns.routing.request/response 内）",
            )),
            Item::Section(s) => match s.name.as_str() {
                "upstream" => {
                    for it in &s.items {
                        match it {
                            Item::Param(p) => {
                                if p.funcs.is_some() {
                                    let mut d = p_loc(cfg, p);
                                    d.msg = "dns.upstream 只接受字符串值".into();
                                    out.push(d);
                                }
                            }
                            other => out.push(err_at(
                                cfg,
                                &s.loc,
                                format!("dns.upstream 不支持：{other:?}"),
                            )),
                        }
                    }
                }
                "routing" => {
                    for it in &s.items {
                        match it {
                            Item::Section(rs) if rs.name == "request" || rs.name == "response" => {
                                validate_dns_flow(cfg, rs, out)
                            }
                            other => out.push(err_at(
                                cfg,
                                &s.loc,
                                format!("dns.routing 只支持 request/response：{other:?}"),
                            )),
                        }
                    }
                }
                other => out.push(err_at(
                    cfg,
                    &s.loc,
                    format!("unexpected key: {other}（dns）"),
                )),
            },
        }
    }
}

fn validate_dns_flow(cfg: &Config, sec: &Section, out: &mut Vec<Diag>) {
    let mut has_fallback = false;
    for item in &sec.items {
        match item {
            Item::Rule(_) => {}
            Item::Param(p) => {
                if p.key.as_deref() == Some("fallback") {
                    has_fallback = true;
                } else {
                    let mut d = p_loc(cfg, p);
                    d.msg = format!(
                        "unexpected key: {}（dns.routing.{}）",
                        p.key.clone().unwrap_or_default(),
                        sec.name
                    );
                    out.push(d);
                }
            }
            Item::Section(s) => out.push(err_at(
                cfg,
                &s.loc,
                format!("dns.routing.{} 不支持子 section：{}", sec.name, s.name),
            )),
        }
    }
    if !has_fallback {
        out.push(err_at(
            cfg,
            &sec.loc,
            format!(
                "dns.routing.{} requires param \"fallback\" but not found",
                sec.name
            ),
        ));
    }
}

fn validate_groups(cfg: &Config, sec: &Section, out: &mut Vec<Diag>) {
    for item in &sec.items {
        let Item::Section(g) = item else {
            let loc = match item {
                Item::Param(p) => p.loc.clone().unwrap_or_else(|| sec.loc.clone()),
                Item::Rule(r) => r.loc.clone(),
                Item::Section(s) => s.loc.clone(),
            };
            out.push(err_at(
                cfg,
                &loc,
                "group 段内应为 `组名 { ... }` 子 section",
            ));
            continue;
        };
        let mut has_policy = false;
        for it in &g.items {
            match it {
                Item::Param(p) => {
                    if p.key.as_deref() == Some("policy") {
                        has_policy = true;
                    }
                    param_key_required(cfg, p, "group", out);
                }
                Item::Section(s) => out.push(err_at(
                    cfg,
                    &s.loc,
                    format!("group.{} 不支持子 section：{}", g.name, s.name),
                )),
                Item::Rule(r) => {
                    out.push(err_at(cfg, &r.loc, format!("group.{} 不支持规则", g.name)))
                }
            }
        }
        if !has_policy {
            out.push(err_at(
                cfg,
                &g.loc,
                format!(
                    "group \"{}\" requires param \"policy\" but not found",
                    g.name
                ),
            ));
        }
    }
}

// ---------------------------------------------------------------- 导出（JSON）

fn function_json(f: &Function) -> serde_json::Value {
    serde_json::json!({
        "name": f.name,
        "not": f.not,
        "params": f.params.iter().map(param_json).collect::<Vec<_>>(),
        "line": f.loc.line,
    })
}

fn param_json(p: &Param) -> serde_json::Value {
    let mut v = serde_json::Map::new();
    if let Some(k) = &p.key {
        v.insert("key".into(), serde_json::Value::String(k.clone()));
    }
    if let Some(val) = &p.val {
        v.insert("value".into(), serde_json::Value::String(val.clone()));
    }
    if let Some(fs) = &p.funcs {
        v.insert(
            "functions".into(),
            serde_json::Value::Array(fs.iter().map(function_json).collect()),
        );
    }
    if !p.annotation.is_empty() {
        v.insert(
            "annotation".into(),
            serde_json::Value::Array(p.annotation.iter().map(param_json).collect()),
        );
    }
    serde_json::Value::Object(v)
}

fn item_json(it: &Item) -> serde_json::Value {
    match it {
        Item::Param(p) => serde_json::json!({"type": "param", "param": param_json(p)}),
        Item::Section(s) => section_json(s),
        Item::Rule(r) => serde_json::json!({
            "type": "rule",
            "and_functions": r.and_functions.iter().map(function_json).collect::<Vec<_>>(),
            "outbound": function_json(&r.outbound),
            "line": r.loc.line,
        }),
    }
}

fn section_json(s: &Section) -> serde_json::Value {
    serde_json::json!({
        "type": "section",
        "name": s.name,
        "items": s.items.iter().map(item_json).collect::<Vec<_>>(),
    })
}

/// 合并后的配置 → JSON（只读导出）。
pub fn to_json(cfg: &Config) -> serde_json::Value {
    serde_json::json!({
        "entry": cfg.entry.display().to_string(),
        "files": cfg.files.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
        "sections": cfg.sections.iter().map(section_json).collect::<Vec<_>>(),
    })
}

// ---------------------------------------------------------------- 路由段 → 数据面子集

/// 取 `dns { upstream { ... } }` 的第一个 upstream 值（如 `udp://dns.example:53`）。
pub fn dns_upstream_url(cfg: &Config) -> Option<String> {
    let dns = cfg.sections.iter().find(|s| s.name == "dns")?;
    for item in &dns.items {
        if let Item::Section(up) = item {
            if up.name == "upstream" {
                for it in &up.items {
                    if let Item::Param(p) = it {
                        if let Some(v) = &p.val {
                            return Some(v.clone());
                        }
                    }
                }
            }
        }
    }
    None
}

#[derive(Debug, Clone)]
pub struct DeferredRule {
    pub loc: Loc,
    pub rule: String,
    pub reason: String,
}

#[derive(Debug, Clone, Default)]
pub struct RoutingExtract {
    /// 可直接喂给 mini-dae 规则编译器的行（mini 语法）
    pub supported: Vec<String>,
    /// 解析成功但数据面尚未实现、未纳入编译的规则（绝不静默丢弃）
    pub deferred: Vec<DeferredRule>,
    /// 组名 → 数据面 outbound 的映射（K3：全部用户组都落到 proxy=0x02）
    pub outbound_map: Vec<(String, String)>,
    /// 路由段的 fallback（已映射的数据面 outbound）
    pub fallback: Option<String>,
}

fn first_val(p: &Param) -> Option<String> {
    p.val.clone()
}

fn map_outbound(cfg_name: &str, extract: &mut RoutingExtract) -> String {
    match cfg_name {
        "direct" => "direct".into(),
        "block" => "block".into(),
        "must_direct" => "direct(must)".into(),
        other => {
            if !extract.outbound_map.iter().any(|(k, _)| k == other) {
                extract
                    .outbound_map
                    .push((other.to_string(), "proxy".into()));
            }
            "proxy".into()
        }
    }
}

/// 把 `routing` 段翻译成 mini-dae 数据面能编译的子集。
/// 规则级原子：任何一项能力缺失 → 整条规则进 deferred（保持语义不被部分执行）。
pub fn extract_routing(cfg: &Config) -> Result<RoutingExtract, Vec<Diag>> {
    let mut extract = RoutingExtract::default();
    let Some(sec) = cfg.sections.iter().find(|s| s.name == "routing") else {
        return Err(vec![diag(None, 0, "缺少 routing 段")]);
    };
    for item in &sec.items {
        match item {
            Item::Rule(rule) => {
                let mut parts = Vec::new();
                let mut deferred_reason: Option<String> = None;
                for f in &rule.and_functions {
                    match translate_function(f, &mut parts) {
                        Ok(()) => {}
                        Err(reason) => {
                            deferred_reason.get_or_insert(reason);
                            break;
                        }
                    }
                }
                if let Some(reason) = deferred_reason {
                    extract.deferred.push(DeferredRule {
                        loc: rule.loc.clone(),
                        rule: rule_text(rule),
                        reason,
                    });
                    continue;
                }
                let outbound = map_outbound(&rule.outbound.name, &mut extract);
                extract
                    .supported
                    .push(format!("{} -> {}", parts.join(" && "), outbound));
            }
            Item::Param(p) if p.key.as_deref() == Some("fallback") => {
                let Some(name) = p.val.clone().or_else(|| {
                    p.funcs
                        .as_ref()
                        .and_then(|fs| fs.first().map(|f| f.name.clone()))
                }) else {
                    return Err(vec![p_loc(cfg, p)]);
                };
                extract.fallback = Some(map_outbound(&name, &mut extract));
            }
            _ => {}
        }
    }
    for d in &mut extract.deferred {
        d.rule = d.rule.clone();
    }
    Ok(extract)
}

fn rule_text(rule: &Rule) -> String {
    let funcs: Vec<String> = rule.and_functions.iter().map(Function::display).collect();
    format!("{} -> {}", funcs.join(" && "), rule.outbound.display())
}

fn param_values(f: &Function) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for p in &f.params {
        if p.key.is_some() {
            return Err(format!(
                "带 key 的参数（如 {}:{}）需要 geodata/域名数据，数据面暂未接入",
                p.key.clone().unwrap_or_default(),
                p.val.clone().unwrap_or_default()
            ));
        }
        if let Some(v) = first_val(p) {
            out.push(v);
        } else {
            return Err("函数参数必须是字符串值".into());
        }
    }
    Ok(out)
}

fn is_ip_cidr(v: &str) -> bool {
    let (addr, plen) = match v.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (v, None),
    };
    let max = if addr.parse::<std::net::Ipv4Addr>().is_ok() {
        32
    } else if addr.parse::<std::net::Ipv6Addr>().is_ok() {
        128
    } else {
        return false;
    };
    match plen {
        Some(p) => p.parse::<u32>().map(|n| n <= max).unwrap_or(false),
        None => true,
    }
}

fn is_mac(v: &str) -> bool {
    let parts: Vec<&str> = v.split(':').collect();
    parts.len() == 6 && parts.iter().all(|p| u8::from_str_radix(p, 16).is_ok())
}

/// 翻译一个匹配函数；失败给出「为什么 defer」的理由。
fn translate_function(f: &Function, parts: &mut Vec<String>) -> Result<(), String> {
    let bang = if f.not { "!" } else { "" };
    match f.name.as_str() {
        "dip" | "sip" => {
            if f.params.is_empty() {
                return Err(format!("{}(...) 需要至少一个参数", f.name));
            }
            let mut vals: Vec<String> = Vec::new();
            for p in &f.params {
                let Some(v) = p.val.clone() else {
                    return Err("函数参数必须是字符串值".into());
                };
                match p.key.as_deref() {
                    // P17a：geoip/ext 在编译期展开（rules.rs + geodata.rs），此处原样透传。
                    Some("geoip") => {
                        if v.is_empty() {
                            return Err(format!("{}(geoip:) 缺少 code", f.name));
                        }
                        vals.push(format!("geoip: {v}"));
                    }
                    Some("ext") => {
                        if !v.contains(':') {
                            return Err(format!("{}(ext:{v}) 需要 file:code 形式", f.name));
                        }
                        vals.push(format!("ext: {v}"));
                    }
                    Some(other) => {
                        return Err(format!(
                            "{}(…) 不认识的 key: {other}（可用 geoip/ext 或裸 CIDR）",
                            f.name
                        ))
                    }
                    None => {
                        if !is_ip_cidr(&v) {
                            return Err(format!("{}({v}) 含非法前缀（需 IPv4/IPv6 CIDR）", f.name));
                        }
                        // P16：v6 前缀含 ':'，mini 规则语法里需要加引号（dae 语法本身不要求）
                        vals.push(if v.contains(':') { format!("'{v}'") } else { v });
                    }
                }
            }
            parts.push(format!("{bang}{}({})", f.name, vals.join(", ")));
            Ok(())
        }
        "dport" | "sport" => {
            let vals = param_values(f)?;
            if vals.is_empty() {
                return Err(format!("{}(...) 需要至少一个参数", f.name));
            }
            for v in &vals {
                let (a, b) = match v.split_once('-') {
                    Some((a, b)) => (a, b),
                    None => (v.as_str(), v.as_str()),
                };
                if a.parse::<u16>().is_err() || b.parse::<u16>().is_err() {
                    return Err(format!("{}({v}) 不是合法端口/端口区间", f.name));
                }
            }
            parts.push(format!("{bang}{}({})", f.name, vals.join(", ")));
            Ok(())
        }
        "l4proto" => {
            let vals = param_values(f)?;
            if !vals.iter().all(|v| v == "tcp" || v == "udp") {
                return Err(format!("l4proto({}) 只支持 tcp/udp", vals.join(", ")));
            }
            parts.push(format!("{bang}l4proto({})", vals.join(", ")));
            Ok(())
        }
        "ipversion" => {
            let vals = param_values(f)?;
            if !vals.iter().all(|v| v == "4" || v == "6") {
                return Err(format!("ipversion({}) 只支持 4/6", vals.join(", ")));
            }
            parts.push(format!("{bang}ipversion({})", vals.join(", ")));
            Ok(())
        }
        "mac" => {
            let vals = param_values(f)?;
            if !vals.iter().all(|v| is_mac(v)) {
                return Err(format!("mac({}) 需要 6 段 MAC", vals.join(", ")));
            }
            let quoted: Vec<String> = vals.iter().map(|v| format!("'{v}'")).collect();
            parts.push(format!("{bang}mac({})", quoted.join(", ")));
            Ok(())
        }
        "domain" => {
            // P3a/P3b-2a：suffix/full/keyword/regex 均可编译（域位图；regex 在
            // mini 规则编译器里编译，非法正则会在启动/重载时硬失败）。
            // P17a：geosite:code[@attr] 与 ext:file:code 在编译期展开为域名参数。
            let mut groups: Vec<(String, Vec<String>)> = Vec::new();
            for p in &f.params {
                let key = p.key.clone().unwrap_or_else(|| "suffix".into());
                let Some(v) = p.val.clone() else {
                    return Err("domain 参数必须是字符串".into());
                };
                let emit: Vec<(String, String)> = match key.as_str() {
                    "suffix" | "full" | "keyword" | "regex" => vec![(key.clone(), v)],
                    "geosite" => {
                        if v.is_empty() {
                            return Err("domain(geosite:) 缺少 code".into());
                        }
                        vec![("geosite".into(), v)]
                    }
                    "ext" => {
                        if !v.contains(':') {
                            return Err(format!("domain(ext:{v}) 需要 file:code 形式"));
                        }
                        vec![("ext".into(), v)]
                    }
                    other => return Err(format!("domain 不认识的 key: {other}")),
                };
                for (k, val) in emit {
                    match groups.iter_mut().find(|(gk, _)| *gk == k) {
                        Some((_, vs)) => vs.push(val),
                        None => groups.push((k, vec![val])),
                    }
                }
            }
            if groups.is_empty() {
                return Err("domain(...) 需要至少一个参数".into());
            }
            let inner: Vec<String> = groups
                .iter()
                .map(|(k, vs)| {
                    let quoted: Vec<String> = vs.iter().map(|v| format!("'{v}'")).collect();
                    format!("{k}: {}", quoted.join(", "))
                })
                .collect();
            parts.push(format!("{bang}domain({})", inner.join(", ")));
            Ok(())
        }
        "pname" => Err("pname 进程名匹配尚未在数据面实现".into()),
        "fallback" => {
            parts.push("fallback".into());
            Ok(())
        }
        other => Err(format!("未知匹配函数：{other}")),
    }
}

// ---------------------------------------------------------------- P15：订阅/节点/组提取

/// 订阅源（`subscription { tag: 'url' }`）。
#[derive(Debug, Clone)]
pub struct SubSpec {
    pub tag: String,
    pub url: String,
}

/// 内联节点（`node { name: 'link' }`）。
#[derive(Debug, Clone)]
pub struct NodeSpec {
    pub name: String,
    pub link: String,
}

/// 节点组（`group { name { filter: ...; policy: ... } }`）。
#[derive(Debug, Clone)]
pub struct GroupSpec {
    pub name: String,
    /// OR 语义：每个元素是一行 filter（AND 组合的 Function 列表）。
    pub filters: Vec<Vec<Function>>,
    /// 策略字符串（`min` / `min_moving_avg` / `min_avg10` / `random` / `fixed(0)`）。
    pub policy: Option<String>,
    pub tcp_check_urls: Vec<String>,
    pub check_interval: Option<String>,
    pub check_tolerance: Option<String>,
}

pub fn subscriptions(cfg: &Config) -> Vec<SubSpec> {
    let mut out = Vec::new();
    for sec in cfg.sections.iter().filter(|s| s.name == "subscription") {
        for item in &sec.items {
            if let Item::Param(p) = item {
                if let (Some(tag), Some(url)) = (p.key.clone(), p.val.clone()) {
                    out.push(SubSpec { tag, url });
                }
            }
        }
    }
    out
}

pub fn inline_nodes(cfg: &Config) -> Vec<NodeSpec> {
    let mut out = Vec::new();
    for sec in cfg.sections.iter().filter(|s| s.name == "node") {
        for item in &sec.items {
            if let Item::Param(p) = item {
                if let (Some(name), Some(link)) = (p.key.clone(), p.val.clone()) {
                    out.push(NodeSpec { name, link });
                }
            }
        }
    }
    out
}

/// `policy: fixed(0)` 在 AST 里是函数调用；归一化成字符串。
fn policy_to_string(p: &Param) -> Option<String> {
    if let Some(v) = &p.val {
        return Some(v.clone());
    }
    let f = p.funcs.as_ref()?.first()?;
    let args: Vec<String> = f.params.iter().filter_map(|a| a.val.clone()).collect();
    Some(if args.is_empty() {
        f.name.clone()
    } else {
        format!("{}({})", f.name, args.join(","))
    })
}

pub fn groups(cfg: &Config) -> Vec<GroupSpec> {
    let mut out = Vec::new();
    for sec in cfg.sections.iter().filter(|s| s.name == "group") {
        for item in &sec.items {
            let Item::Section(g) = item else { continue };
            let mut spec = GroupSpec {
                name: g.name.clone(),
                filters: Vec::new(),
                policy: None,
                tcp_check_urls: Vec::new(),
                check_interval: None,
                check_tolerance: None,
            };
            for it in &g.items {
                let Item::Param(p) = it else { continue };
                match p.key.as_deref() {
                    Some("filter") => {
                        if let Some(funcs) = &p.funcs {
                            spec.filters.push(funcs.clone());
                        }
                    }
                    Some("policy") => spec.policy = policy_to_string(p),
                    Some("tcp_check_url") => {
                        if let Some(v) = &p.val {
                            spec.tcp_check_urls.extend(
                                v.split(',')
                                    .map(|s| s.trim().to_string())
                                    .filter(|s| !s.is_empty()),
                            );
                        }
                    }
                    Some("check_interval") => spec.check_interval = p.val.clone(),
                    Some("check_tolerance") => spec.check_tolerance = p.val.clone(),
                    _ => {}
                }
            }
            out.push(spec);
        }
    }
    out
}

// ---------------------------------------------------------------- 测试

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(src: &str) -> Result<Vec<Section>, Vec<Diag>> {
        parse_text(src, Path::new("test.dae"), 0)
    }

    #[test]
    fn parses_full_dsl() {
        let src = r#"
# 注释
include {
    conf.d/*.dae
}
global {
    wan_interface: auto
    tproxy_port: 12345
    lan_interface: 'br0,br1'
    udp_check_dns: 'dns.google:53,8.8.8.8'
}
subscription {
    my_sub: 'https://example.com/sub'
    'https://example.com/bare'
}
node {
    hk1: 'ss://xxx#HK-1'
}
group {
    proxy {
        filter: name(keyword: 'HK') && !name(keyword: 'Expire')
        filter: name(US_node) [add_latency: -500ms]
        policy: min_moving_avg
    }
}
dns {
    upstream {
        alidns: 'udp://dns.alidns.com:53'
    }
    routing {
        request {
            qname(geosite:cn) -> alidns
            subnode(subtag: my_sub, name_keyword: hk) -> alidns
            fallback: alidns
        }
        response {
            fallback: alidns
        }
    }
}
routing {
    sip(192.168.0.0/24) && !sip(192.168.0.252/30) -> direct
    dport(8000-9000, 443) -> proxy
    domain(suffix: example.com) -> proxy
    dip(geoip:cn) -> direct
    l4proto(udp) && dport(53) -> proxy(must)
    fallback: proxy
}
"#;
        let secs = parse(src).expect("parse ok");
        let names: Vec<&str> = secs.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "include",
                "global",
                "subscription",
                "node",
                "group",
                "dns",
                "routing"
            ]
        );
        // group filter 注解
        let group = &secs[4];
        let Item::Section(proxy) = &group.items[0] else {
            panic!("group 应为子 section");
        };
        let filters: Vec<&Param> = proxy
            .items
            .iter()
            .filter_map(|i| match i {
                Item::Param(p) if p.key.as_deref() == Some("filter") => Some(p),
                _ => None,
            })
            .collect();
        assert_eq!(filters.len(), 2);
        assert_eq!(filters[1].annotation.len(), 1);
        assert_eq!(filters[1].annotation[0].key.as_deref(), Some("add_latency"));
        assert_eq!(filters[1].annotation[0].val.as_deref(), Some("-500ms"));
        // routing：6 items（5 规则 + fallback），sip 规则带取反
        let routing = &secs[6];
        let rules: Vec<&Rule> = routing
            .items
            .iter()
            .filter_map(|i| match i {
                Item::Rule(r) => Some(r),
                _ => None,
            })
            .collect();
        assert_eq!(rules.len(), 5);
        assert!(rules[0].and_functions[1].not);
        assert_eq!(rules[1].and_functions[0].params.len(), 2);
        assert_eq!(
            rules[1].and_functions[0].params[0].val.as_deref(),
            Some("8000-9000")
        );
        assert_eq!(rules[4].outbound.name, "proxy");
        assert_eq!(rules[4].outbound.params.len(), 1);
    }

    #[test]
    fn rejects_unclosed_braces_and_quotes() {
        assert!(parse("global {").is_err());
        assert!(parse("global { x: 'oops }").is_err());
        assert!(parse("/* never ends").is_err());
    }

    #[test]
    fn validate_unknown_and_required() {
        let secs = parse(
            "global { nope: 1 }\nrouting { fallback: direct }\ngroup { g { filter: name(a) } }\n",
        )
        .unwrap();
        let cfg = Config {
            entry: PathBuf::from("t.dae"),
            files: vec![PathBuf::from("t.dae")],
            sections: secs,
        };
        let diags = validate(&cfg);
        let msg = diags
            .iter()
            .map(|d| d.msg.clone())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(msg.contains("unexpected key: nope"), "{msg}");
        assert!(msg.contains("requires param \"policy\""), "{msg}");

        let secs = parse("global { tproxy_port: 1 }\n").unwrap();
        let cfg = Config {
            entry: PathBuf::from("t.dae"),
            files: vec![PathBuf::from("t.dae")],
            sections: secs,
        };
        let msg = validate(&cfg)
            .iter()
            .map(|d| d.msg.clone())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(msg.contains("section routing is required"), "{msg}");
    }

    #[test]
    fn extract_routing_maps_and_defers() {
        let secs = parse(
            r#"global {}
routing {
    sip(192.168.0.0/24) && !sip(192.168.0.252/30) -> direct
    dip(10.9.10.0/24) && dport(9999) -> direct
    domain(suffix: example.com) -> proxy
    domain(regex: '^api[0-9]+\\.example\\.com$') -> proxy
    dip(geoip:cn) -> direct
    l4proto(udp) && dport(53) -> mystery_group
    mac('aa:bb:cc:dd:ee:ff') -> direct
    fallback: mystery_group
}"#,
        )
        .unwrap();
        let cfg = Config {
            entry: PathBuf::from("t.dae"),
            files: vec![PathBuf::from("t.dae")],
            sections: secs,
        };
        let ex = extract_routing(&cfg).unwrap();
        assert_eq!(ex.supported.len(), 7, "{:#?}", ex.supported);
        assert!(ex.supported[0].starts_with("sip(192.168.0.0/24) && !sip("));
        assert_eq!(ex.supported[2], "domain(suffix: 'example.com') -> proxy");
        assert_eq!(
            ex.supported[3],
            "domain(regex: '^api[0-9]+\\.example\\.com$') -> proxy"
        );
        // P17a：geoip 从 deferred 变为可编译（展开在编译期，配置层原样透传）
        assert_eq!(ex.supported[4], "dip(geoip: cn) -> direct");
        assert_eq!(ex.supported[6], "mac('aa:bb:cc:dd:ee:ff') -> direct");
        assert!(ex.deferred.is_empty(), "{:#?}", ex.deferred);
        assert_eq!(ex.fallback.as_deref(), Some("proxy"));
        assert!(ex
            .outbound_map
            .iter()
            .any(|(k, v)| k == "mystery_group" && v == "proxy"));
    }

    #[test]
    fn extract_routing_geo_ext_keys() {
        let secs = parse(
            r#"global {}
routing {
    dip(geoip:cn) -> direct
    dip(ext:mygeo.dat:cn) -> direct
    domain(geosite:cn) -> proxy
    domain(geosite:geolocation-!cn@ads) -> proxy
    domain(ext:mysite.dat:cn@ads) -> proxy
    fallback: direct
}"#,
        )
        .unwrap();
        let cfg = Config {
            entry: PathBuf::from("t.dae"),
            files: vec![PathBuf::from("t.dae")],
            sections: secs,
        };
        let ex = extract_routing(&cfg).unwrap();
        assert_eq!(ex.supported.len(), 5, "{:#?}", ex.supported);
        assert_eq!(ex.supported[0], "dip(geoip: cn) -> direct");
        assert_eq!(ex.supported[1], "dip(ext: mygeo.dat:cn) -> direct");
        assert_eq!(ex.supported[2], "domain(geosite: 'cn') -> proxy");
        assert_eq!(
            ex.supported[3],
            "domain(geosite: 'geolocation-!cn@ads') -> proxy"
        );
        assert_eq!(ex.supported[4], "domain(ext: 'mysite.dat:cn@ads') -> proxy");
        assert!(ex.deferred.is_empty(), "{:#?}", ex.deferred);
    }

    #[test]
    fn include_merge_and_cycle_and_perms() {
        let dir = std::env::temp_dir().join(format!("mini-dae-cfg-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let entry = dir.join("main.dae");
        let child = dir.join("child.dae");
        fs::write(
            &entry,
            "include { child.dae }\nglobal { tproxy_port: 1 }\nrouting { fallback: direct }\n",
        )
        .unwrap();
        fs::write(
            &child,
            "global { log_level: info }\nrouting { dport(80) -> direct }\n",
        )
        .unwrap();
        for f in [&entry, &child] {
            fs::set_permissions(f, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let cfg = load(&entry).expect("load ok");
        assert_eq!(cfg.files.len(), 2);
        let global = cfg.sections.iter().find(|s| s.name == "global").unwrap();
        assert_eq!(global.items.len(), 2, "父在前、子在后合并");
        let routing = cfg.sections.iter().find(|s| s.name == "routing").unwrap();
        assert_eq!(routing.items.len(), 2);

        // 循环包含
        fs::write(&child, "include { main.dae }\n").unwrap();
        let err = load(&entry).unwrap_err();
        assert!(err[0].msg.contains("circular include"), "{}", err[0].msg);

        // 权限过宽
        fs::write(&child, "global {}\n").unwrap();
        fs::set_permissions(&child, fs::Permissions::from_mode(0o644)).unwrap();
        let err = load(&entry).unwrap_err();
        assert!(err[0].msg.contains("权限"), "{}", err[0].msg);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn glob_matcher() {
        assert!(glob_match("*.dae", "a.dae"));
        assert!(glob_match("a?c", "abc"));
        assert!(!glob_match("a?c", "abbc"));
        assert!(glob_match("[a-c]x", "bx"));
        assert!(!glob_match("[!a-c]x", "bx"));
    }
}
