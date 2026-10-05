//! M3：配置 / 规则文件在线编辑（先校验后落盘，保存即热重载）。

use leptos::prelude::*;
use shared::{FileContent, FileInfo, SaveResult};

use crate::{get_json, post_json};

#[derive(Clone, Default)]
pub struct EditorState {
    pub open: bool,
    pub files: Vec<FileInfo>,
    pub current: String,
    pub text: String,
    pub result: Option<SaveResult>,
    pub busy: bool,
}

pub fn open_editor(state: RwSignal<EditorState>, token: RwSignal<Option<String>>) {
    let need = {
        let s = state.get_untracked();
        !s.open || s.files.is_empty()
    };
    state.update(|s| s.open = true);
    if need {
        refresh_files(state, token);
    }
}

pub fn refresh_files(state: RwSignal<EditorState>, token: RwSignal<Option<String>>) {
    let tok = token.get_untracked();
    leptos::task::spawn_local(async move {
        let Ok(v) = get_json::<serde_json::Value>("/api/v1/files", tok.as_deref()).await else {
            return;
        };
        let Some(arr) = v.get("files").and_then(|f| f.as_array()) else {
            return;
        };
        let files: Vec<FileInfo> = arr
            .iter()
            .filter_map(|x| serde_json::from_value(x.clone()).ok())
            .collect();
        let empty = state.get_untracked().files.is_empty();
        state.update(|s| s.files = files);
        if empty {
            if let Some(name) = state.get_untracked().files.first().map(|f| f.name.clone()) {
                load_file(state, token, name);
            }
        }
    });
}

pub fn load_file(state: RwSignal<EditorState>, token: RwSignal<Option<String>>, name: String) {
    let tok = token.get_untracked();
    state.update(|s| {
        s.current = name.clone();
        s.result = None;
    });
    leptos::task::spawn_local(async move {
        let path = format!("/api/v1/files/content?name={name}");
        if let Ok(v) = get_json::<FileContent>(&path, tok.as_deref()).await {
            state.update(|s| s.text = v.text);
        }
    });
}

#[component]
pub fn EditorModal(state: RwSignal<EditorState>, token: RwSignal<Option<String>>) -> impl IntoView {
    view! {
        {move || state.get().open.then(|| view! {
            <div class="modal-mask">
                <div class="modal">
                    <div class="modal-head">
                        <span class="panel-title">"配置 / 规则编辑"</span>
                        <span class="panel-meta">
                            {move || format!("{} · 保存后自动校验 + 引擎热重载", state.get().current)}
                        </span>
                        <div class="modal-actions">
                            <button class="btn" on:click=move |_| refresh_files(state, token)>"刷新"</button>
                            <button class="btn" on:click=move |_| state.update(|s| s.open = false)>"关闭"</button>
                        </div>
                    </div>
                    <div class="modal-body">
                        <div class="file-list">
                            <For each=move || state.get().files key=|f| f.name.clone() children=move |f| {
                                let n1 = f.name.clone();
                                let n2 = f.name.clone();
                                let cls = move || {
                                    if state.get().current == n1 { "file-item file-item-on" } else { "file-item" }
                                };
                                view! {
                                    <div class=cls on:click=move |_| load_file(state, token, n2.clone())>
                                        <span class="mono">{f.name.clone()}</span>
                                        <span class="mono dim">{format!("{}B", f.size)}</span>
                                    </div>
                                }
                            }/>
                        </div>
                        <div class="editor-pane">
                            <textarea class="editor" spellcheck="false"
                                prop:value=move || state.get().text
                                on:input=move |ev| {
                                    let v = event_target_value(&ev);
                                    state.update(|s| s.text = v);
                                }></textarea>
                            <div class="editor-foot">
                                <button class="btn btn-primary" disabled=move || state.get().busy
                                    on:click=move |_| {
                                        let (name, text) = {
                                            let s = state.get();
                                            (s.current.clone(), s.text.clone())
                                        };
                                        let tok = token.get_untracked();
                                        state.update(|s| {
                                            s.busy = true;
                                            s.result = None;
                                        });
                                        leptos::task::spawn_local(async move {
                                            let body = serde_json::json!({"name": name, "text": text});
                                            let r = post_json::<_, SaveResult>("/api/v1/files/content", &body, tok.as_deref()).await;
                                            state.update(|s| {
                                                s.busy = false;
                                                s.result = Some(match r {
                                                    Ok(v) => v,
                                                    Err(e) => SaveResult { ok: false, message: e, reload_ok: None },
                                                });
                                            });
                                        });
                                    }>
                                    {move || if state.get().busy { "保存中…" } else { "保存并生效" }}
                                </button>
                                {move || state.get().result.map(|r| {
                                    let cls = if r.ok { "save-msg save-ok" } else { "save-msg save-err" };
                                    let reload = match r.reload_ok {
                                        Some(true) => " · 热重载 ✓",
                                        Some(false) => " · 热重载失败",
                                        None => "",
                                    };
                                    view! { <span class=cls>{format!("{}{}", r.message, reload)}</span> }
                                })}
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        })}
    }
}
