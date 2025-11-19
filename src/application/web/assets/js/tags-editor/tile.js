/*
 * tags-editor/tile.js
 *
 * Implémente la logique d'édition (description + tags) pour une tuile donnée.
 */
(function (global) {
  const tags = (global.DescribeMe && global.DescribeMe.tags) || null;
  if (!tags) {
    return;
  }
  const {
    DESCRIPTION_MAX_CHARS,
    TAGS_MAX,
    TAG_LENGTH_LIMIT,
    DEFAULT_DESC_ENDPOINT,
    DEFAULT_TAG_ENDPOINT,
    TAG_OP_SET,
    sanitizeDescription,
    arraysEqual,
    dedupeTags,
    parseInputTags,
    appendServerParam,
    readJsonMessage,
  } = tags;

  class TagsEditorTile {
    constructor(root, options = {}) {
      this.root = root;
      this.descriptionEndpoint =
        root.dataset.descriptionEndpoint ||
        options.descriptionEndpoint ||
        DEFAULT_DESC_ENDPOINT;
      this.tagsEndpoint =
        root.dataset.tagsEndpoint || options.tagsEndpoint || DEFAULT_TAG_ENDPOINT;
      this.serverId = (root.dataset.serverId || options.serverId || "").trim();

      this.descView = root.querySelector("[data-role='desc-view']");
      this.descEmpty = root.querySelector("[data-role='desc-empty']");
      this.descInput = root.querySelector("[data-role='desc-input']");
      this.descHint = root.querySelector("[data-role='desc-hint']");
      this.tagList = root.querySelector("[data-role='tag-list']");
      this.tagEmpty = root.querySelector("[data-role='tag-empty']");
      this.tagEditor = root.querySelector("[data-role='tag-editor']");
      this.tagInput = root.querySelector("[data-role='tag-input']");
      this.tagHint = root.querySelector("[data-role='tag-hint']");
      this.tagClearBtn = root.querySelector("[data-role='tag-clear']");
      this.editButton = root.querySelector("button.edit");
      this.saveButton = root.querySelector("button.save");
      this.cancelButton = root.querySelector("button.cancel");
      this.tagForm = this.tagEditor;

      this.isEditing = false;
      this.isSavingDescription = false;
      this.isSavingTags = false;
      this.remoteDescription = "";
      this.remoteTags = [];
      this.editingTags = [];
      this.tagsDirty = false;

      this.bindEvents();
      this.renderDescription("");
      this.renderTags([]);
    }

    bindEvents() {
      if (this.editButton) {
        this.editButton.addEventListener("click", () => this.enterEditMode());
      }
      if (this.cancelButton) {
        this.cancelButton.addEventListener("click", () =>
          this.exitEditMode(true)
        );
      }
      if (this.saveButton) {
        this.saveButton.addEventListener("click", () => this.saveDescription());
      }
      if (this.tagForm && this.tagInput) {
        this.tagForm.addEventListener("submit", (event) => {
          event.preventDefault();
          this.handleTagsSubmit();
        });
      }
      if (this.tagClearBtn) {
        this.tagClearBtn.addEventListener("click", (event) => {
          event.preventDefault();
          this.handleTagsClear();
        });
      }
    }

    applySnapshot(snapshot) {
      const nextDescription =
        typeof snapshot.description === "string" ? snapshot.description : "";
      const nextTags = Array.isArray(snapshot.tags)
        ? snapshot.tags
            .map((tag) => (typeof tag === "string" ? tag.trim() : ""))
            .filter((tag) => tag.length > 0)
        : [];
      this.remoteDescription = nextDescription;
      this.remoteTags = dedupeTags(nextTags);
      if (!this.isEditing) {
        this.renderDescription(this.remoteDescription);
        this.renderTags(this.remoteTags);
      }
    }

    enterEditMode() {
      if (this.isEditing || this.isSavingDescription || this.isSavingTags) {
        return;
      }
      this.isEditing = true;
      this.editingTags = [...this.remoteTags];
      this.tagsDirty = false;
      if (this.descInput) {
        this.descInput.hidden = false;
        this.descInput.value = this.remoteDescription;
        this.descInput.focus();
      }
      if (this.descView) {
        this.descView.hidden = true;
      }
      if (this.descEmpty) {
        this.descEmpty.hidden = true;
      }
      if (this.tagEditor) {
        this.tagEditor.hidden = false;
      }
      if (this.editButton) {
        this.editButton.hidden = true;
      }
      if (this.saveButton) {
        this.saveButton.hidden = false;
      }
      if (this.cancelButton) {
        this.cancelButton.hidden = false;
      }
      this.renderTags(this.editingTags);
      this.setDescHint("");
      this.setTagHint("");
    }

    exitEditMode(resetFields = true, clearHints = true) {
      if (!this.isEditing) {
        return;
      }
      this.isEditing = false;
      this.editingTags = [...this.remoteTags];
      this.tagsDirty = false;
      if (this.descInput) {
        this.descInput.hidden = true;
        this.descInput.disabled = false;
        if (resetFields) {
          this.descInput.value = this.remoteDescription;
        }
      }
      if (this.descView) {
        this.descView.hidden = false;
      }
      if (this.descEmpty) {
        this.descEmpty.hidden = this.remoteDescription.trim().length > 0;
      }
      if (this.tagEditor) {
        this.tagEditor.hidden = true;
      }
      if (this.editButton) {
        this.editButton.hidden = false;
      }
      if (this.saveButton) {
        this.saveButton.hidden = true;
        this.saveButton.disabled = false;
      }
      if (this.cancelButton) {
        this.cancelButton.hidden = true;
      }
      if (resetFields && this.tagInput) {
        this.tagInput.value = "";
      }
      this.renderDescription(this.remoteDescription);
      this.renderTags(this.remoteTags);
      if (clearHints) {
        this.setDescHint("");
        this.setTagHint("");
      }
    }

    renderDescription(value) {
      const text = value || "";
      const trimmed = text.trim();
      if (this.descView) {
        this.descView.textContent = text;
        this.descView.hidden = trimmed.length === 0;
      }
      if (this.descEmpty) {
        this.descEmpty.hidden = trimmed.length > 0;
      }
      if (!this.isEditing && this.descInput) {
        this.descInput.value = text;
        this.descInput.hidden = true;
      }
    }

    renderTags(list) {
      if (!this.tagList || !this.tagEmpty) {
        return;
      }
      while (this.tagList.firstChild) {
        this.tagList.removeChild(this.tagList.firstChild);
      }
      const tagsList = Array.isArray(list) ? list : [];
      if (tagsList.length === 0) {
        this.tagEmpty.hidden = false;
        return;
      }
      this.tagEmpty.hidden = true;
      const fragment = document.createDocumentFragment();
      tagsList.forEach((tag) => {
        const value = typeof tag === "string" ? tag : "";
        if (!value) {
          return;
        }
        const pill = document.createElement("span");
        pill.className = "tag tag-pill";
        pill.appendChild(document.createTextNode(value));
        if (this.isEditing) {
          const remove = document.createElement("button");
          remove.type = "button";
          remove.className = "tag-remove";
          remove.setAttribute("aria-label", `Supprimer ${value}`);
          remove.textContent = "×";
          remove.addEventListener("click", () => this.removeTag(value));
          pill.appendChild(remove);
        }
        fragment.appendChild(pill);
      });
      this.tagList.appendChild(fragment);
    }

    setDescHint(message, tone = "") {
      if (!this.descHint) {
        return;
      }
      this.descHint.textContent = message || "";
      this.descHint.classList.remove("error", "success");
      if (tone) {
        this.descHint.classList.add(tone);
      }
    }

    setTagHint(message, tone = "") {
      if (!this.tagHint) {
        return;
      }
      this.tagHint.textContent = message || "";
      this.tagHint.classList.remove("error", "success");
      if (tone) {
        this.tagHint.classList.add(tone);
      }
    }

    async saveDescription() {
      if (!this.descInput || this.isSavingDescription) {
        return;
      }
      const normalized = sanitizeDescription(this.descInput.value || "");
      if (normalized.length > DESCRIPTION_MAX_CHARS) {
        this.setDescHint(
          `La description ne peut pas dépasser ${DESCRIPTION_MAX_CHARS} caractères.`,
          "error"
        );
        return;
      }
      this.isSavingDescription = true;
      this.setDescHint("Enregistrement…");
      if (this.saveButton) {
        this.saveButton.disabled = true;
      }
      if (this.descInput) {
        this.descInput.disabled = true;
      }
      try {
        const headers = { "Content-Type": "application/json" };
        if (typeof currentToken === "string" && currentToken) {
          headers["Authorization"] = `Bearer ${currentToken}`;
        }
        const response = await fetch(
          appendServerParam(this.descriptionEndpoint, this.serverId),
          {
            method: "POST",
            headers,
            credentials: "same-origin",
            body: JSON.stringify({ text: normalized }),
          }
        );
        if (response.status === 401) {
          const message = await readJsonMessage(response);
          if (typeof showTokenPrompt === "function") {
            showTokenPrompt(
              message || "Jeton requis pour modifier la description."
            );
          }
          return;
        }
        if (response.status === 403) {
          const message = await readJsonMessage(response);
          this.setDescHint(message || "Adresse IP non autorisée.", "error");
          return;
        }
        const data = await response.json().catch(() => ({}));
        if (!response.ok) {
          const message =
            (data && typeof data.error === "string" && data.error) ||
            "Impossible d'enregistrer la description.";
          this.setDescHint(message, "error");
          return;
        }
        const value =
          data && typeof data.description === "string"
            ? data.description
            : normalized;
        this.remoteDescription = value;
        this.setDescHint("Description mise à jour.", "success");
        this.exitEditMode(false, false);
        this.renderDescription(this.remoteDescription);
      } catch (_) {
        this.setDescHint("Impossible d'enregistrer la description.", "error");
      } finally {
        this.isSavingDescription = false;
        if (this.saveButton) {
          this.saveButton.disabled = false;
        }
        if (this.descInput) {
          this.descInput.disabled = false;
        }
      }
    }

    handleTagsSubmit() {
      if (!this.isEditing) {
        this.enterEditMode();
      }
      if (this.isSavingTags || !this.tagInput) {
        return;
      }
      const tokens = parseInputTags(this.tagInput.value).map((token) => token);
      if (tokens.length > 0) {
        const candidate = dedupeTags([...this.editingTags, ...tokens]);
        if (candidate.length > TAGS_MAX) {
          this.setTagHint(
            `Impossible d'ajouter plus de ${TAGS_MAX} tags.`,
            "error"
          );
          return;
        }
        this.editingTags = candidate;
        this.renderTags(this.editingTags);
      }
      this.tagsDirty = !arraysEqual(this.editingTags, this.remoteTags);
      if (!this.tagsDirty) {
        this.setTagHint("Aucun changement détecté.", "error");
        return;
      }
      this.persistTags(this.editingTags);
    }

    handleTagsClear() {
      if (!this.isEditing) {
        this.enterEditMode();
      }
      if (this.isSavingTags) {
        return;
      }
      if (this.editingTags.length === 0) {
        this.setTagHint("Aucun tag à effacer.", "error");
        return;
      }
      this.editingTags = [];
      this.tagsDirty = true;
      this.renderTags(this.editingTags);
      this.persistTags(this.editingTags);
    }

    removeTag(value) {
      if (!this.isEditing || this.isSavingTags) {
        return;
      }
      const next = this.editingTags.filter((tag) => tag !== value);
      if (next.length === this.editingTags.length) {
        return;
      }
      this.editingTags = next;
      this.tagsDirty = !arraysEqual(this.editingTags, this.remoteTags);
      this.renderTags(this.editingTags);
    }

    validateTagsCollection(tags) {
      if (tags.length > TAGS_MAX) {
        return `La liste ne peut pas dépasser ${TAGS_MAX} tags.`;
      }
      if (tags.some((tag) => tag.length === 0 || tag.length > TAG_LENGTH_LIMIT)) {
        return `Chaque tag doit contenir entre 1 et ${TAG_LENGTH_LIMIT} caractères.`;
      }
      return null;
    }

    disableTagControls(disabled) {
      if (this.tagInput) {
        this.tagInput.disabled = disabled;
      }
      if (this.tagClearBtn) {
        this.tagClearBtn.disabled = disabled;
      }
      if (this.tagForm) {
        const buttons = this.tagForm.querySelectorAll("button");
        buttons.forEach((btn) => {
          btn.disabled = disabled;
        });
      }
    }

    async persistTags(nextTags) {
      const normalized = dedupeTags(
        nextTags
          .map((tag) => (typeof tag === "string" ? tag.trim() : ""))
          .filter((tag) => tag.length > 0)
      );
      const validationError = this.validateTagsCollection(normalized);
      if (validationError) {
        this.setTagHint(validationError, "error");
        return;
      }
      if (arraysEqual(normalized, this.remoteTags)) {
        this.setTagHint("Aucun changement détecté.", "error");
        return;
      }
      this.isSavingTags = true;
      this.setTagHint("Enregistrement…");
      this.disableTagControls(true);
      try {
        const headers = { "Content-Type": "application/json" };
        if (typeof currentToken === "string" && currentToken) {
          headers["Authorization"] = `Bearer ${currentToken}`;
        }
        const response = await fetch(
          appendServerParam(this.tagsEndpoint, this.serverId),
          {
            method: "POST",
            headers,
            credentials: "same-origin",
            body: JSON.stringify({ op: TAG_OP_SET, tags: normalized }),
          }
        );
        if (response.status === 401) {
          const message = await readJsonMessage(response);
          if (typeof showTokenPrompt === "function") {
            showTokenPrompt(
              message || "Jeton requis pour modifier les tags."
            );
          }
          return;
        }
        if (response.status === 403) {
          const message = await readJsonMessage(response);
          this.setTagHint(message || "Adresse IP non autorisée.", "error");
          return;
        }
        const data = await response.json().catch(() => ({}));
        if (!response.ok) {
          const message =
            (data && typeof data.error === "string" && data.error) ||
            "Impossible de mettre à jour les tags.";
          this.setTagHint(message, "error");
          return;
        }
        const next =
          Array.isArray(data.tags) && data.tags.length > 0
            ? data.tags
                .map((tag) => (typeof tag === "string" ? tag.trim() : ""))
                .filter((tag) => tag.length > 0)
            : normalized;
        this.remoteTags = dedupeTags(next);
        this.editingTags = [...this.remoteTags];
        this.tagsDirty = false;
        if (this.tagInput) {
          this.tagInput.value = "";
        }
        this.exitEditMode(false, false);
        this.renderTags(this.remoteTags);
        this.setTagHint("Tags mis à jour.", "success");
      } catch (_) {
        this.setTagHint("Impossible de mettre à jour les tags.", "error");
      } finally {
        this.isSavingTags = false;
        this.disableTagControls(false);
      }
    }
  }

  tags.TagsEditorTile = TagsEditorTile;
})(window);
