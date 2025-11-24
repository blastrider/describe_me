pub const BACKGROUND_CANVAS_JS: &str = include_str!("js/background-grid.js");

pub const LOGS_JS: &str = include_str!("js/logs.js");

pub const MAIN_JS: &str = concat!(
    include_str!("js/preamble.js"),
    "\n",
    include_str!("js/drag.js"),
    "\n",
    include_str!("js/token.js"),
    "\n",
    include_str!("js/tags-editor/helpers.js"),
    "\n",
    include_str!("js/tags-editor/tile.js"),
    "\n",
    include_str!("js/tags-editor/manager.js"),
    "\n",
    include_str!("js/disk-utils.js"),
    "\n",
    include_str!("js/history-trends.js"),
    "\n",
    include_str!("js/logs.js"),
    "\n",
    include_str!("js/ui.js"),
    "\n",
    include_str!("js/sse.js"),
    "\n",
    include_str!("js/bootstrap.js"),
    "\n"
);
pub const LOGO_SVG: &[u8] = include_bytes!("gen.svg");
