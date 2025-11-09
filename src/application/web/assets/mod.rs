pub const MAIN_JS: &str = concat!(
    include_str!("js/preamble.js"),
    "\n",
    include_str!("js/drag.js"),
    "\n",
    include_str!("js/token.js"),
    "\n",
    include_str!("js/ui.js"),
    "\n",
    include_str!("js/sse.js"),
    "\n",
    include_str!("js/bootstrap.js"),
    "\n"
);
pub const LOGO_SVG: &[u8] = include_bytes!("logo.svg");
