/*
 * tags-editor/helpers.js
 *
 * Constantes et helpers partagés entre les différents modules TagsEditor.
 */
(function (global) {
  const DescribeMe = (global.DescribeMe = global.DescribeMe || {});
  const tags = (DescribeMe.tags = DescribeMe.tags || {});

  Object.assign(tags, {
    DESCRIPTION_MAX_BYTES: 2048,
    TAGS_MAX: 64,
    TAG_LENGTH_LIMIT: 48,
    DEFAULT_DESC_ENDPOINT: "/api/description",
    DEFAULT_TAG_ENDPOINT: "/api/tags",
    TAG_OP_SET: "set",
    sanitizeDescription(value) {
      return String(value ?? "").replace(/\r\n/g, "\n").replace(/\r/g, "\n");
    },
    arraysEqual(a, b) {
      if (a.length !== b.length) {
        return false;
      }
      for (let i = 0; i < a.length; i += 1) {
        if (a[i] !== b[i]) {
          return false;
        }
      }
      return true;
    },
    dedupeTags(list) {
      const seen = new Set();
      const out = [];
      list.forEach((tag) => {
        if (!seen.has(tag)) {
          seen.add(tag);
          out.push(tag);
        }
      });
      return out;
    },
    parseInputTags(raw) {
      return String(raw || "")
        .split(/[\,\s]+/)
        .map((token) => token.trim())
        .filter((token) => token.length > 0);
    },
    appendServerParam(url, serverId) {
      if (!serverId) {
        return url;
      }
      try {
        const absolute = new URL(url, window.location.origin);
        absolute.searchParams.set("server", serverId);
        return absolute.toString();
      } catch (_) {
        const separator = url.includes("?") ? "&" : "?";
        return `${url}${separator}server=${encodeURIComponent(serverId)}`;
      }
    },
    descriptionByteLength(value) {
      const text = String(value ?? "");
      if (typeof TextEncoder !== "undefined") {
        return new TextEncoder().encode(text).length;
      }
      return encodeURIComponent(text).replace(/%[0-9A-F]{2}/g, "x").length;
    },
    async readJsonMessage(response) {
      try {
        const text = await response.text();
        if (!text) {
          return "";
        }
        const data = JSON.parse(text);
        if (data && typeof data.error === "string") {
          return data.error;
        }
        return text;
      } catch (_) {
        return "";
      }
    },
  });
})(window);
