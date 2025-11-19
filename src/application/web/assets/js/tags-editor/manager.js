/*
 * tags-editor/manager.js
 *
 * Point d'entrée instanciant les tuiles et exposant TagsEditorManager.
 */
(function (global) {
  const tags = (global.DescribeMe && global.DescribeMe.tags) || {};
  const Tile = tags.TagsEditorTile;
  if (typeof Tile !== "function") {
    return;
  }

  class TagsEditorManager {
    constructor({ selector = "[data-tags-editor]" } = {}) {
      this.tiles = Array.from(document.querySelectorAll(selector)).map(
        (node) => new Tile(node)
      );
    }

    applySnapshot(payload) {
      const description =
        typeof payload.description === "string" ? payload.description : "";
      const tagsList = Array.isArray(payload.tags) ? payload.tags : [];
      this.tiles.forEach((tile) => tile.applySnapshot({
        description,
        tags: tagsList,
      }));
    }
  }

  global.TagsEditorManager = TagsEditorManager;
  tags.TagsEditorManager = TagsEditorManager;
})(window);
