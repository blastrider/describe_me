use std::fs;

fn read(path: &str) -> String {
    fs::read_to_string(path).unwrap_or_else(|err| panic!("read {} failed: {err}", path))
}

#[test]
fn html_marks_sensitive_containers() {
    let html = read("src/application/web/templates/partials/main_layout.html");
    assert!(
        html.contains("data-sensitive=\"1\""),
        "expected data-sensitive attribute in template"
    );
    assert!(
        html.contains("class=\"blurred\""),
        "expected blurred class applied at render time"
    );
}

#[test]
fn css_defines_blur_style() {
    let css = read("src/application/web/templates/styles/base.css");
    assert!(
        css.contains("filter: blur"),
        "blur filter missing from stylesheet"
    );
}

#[test]
fn javascript_handles_blur_transitions() {
    let js = read("src/application/web/assets/js/token.js");
    assert!(
        js.contains("sensitiveNodes.forEach((node) => node.classList.add('blurred'))"),
        "JS should add blurred class when prompting for token"
    );
    assert!(
        js.contains("sensitiveNodes.forEach((node) => node.classList.remove('blurred'))"),
        "JS should remove blurred class once authenticated"
    );
}
