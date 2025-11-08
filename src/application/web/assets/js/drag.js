const dragState = {
  card: null,
  zone: null,
};

const clearDropIndicators = () => {
  document
    .querySelectorAll('.card-drop-before, .card-drop-after')
    .forEach((node) => node.classList.remove('card-drop-before', 'card-drop-after'));
};

const handleCardDragStart = function (event) {
  const zone = this.closest('[data-draggable-zone]');
  if (!zone) {
    event.preventDefault();
    return;
  }
  dragState.card = this;
  dragState.zone = zone;
  this.classList.add('dragging');
  event.dataTransfer.effectAllowed = 'move';
  try {
    event.dataTransfer.setData('text/plain', this.id || 'card');
  } catch (_) {
    // Safari peut lancer une exception si aucun type n'est accepté.
  }
};

const handleCardDragEnd = function () {
  this.classList.remove('dragging');
  dragState.card = null;
  dragState.zone = null;
  clearDropIndicators();
};

const handleCardDragOver = function (event) {
  if (!dragState.card || dragState.card === this) {
    return;
  }
  if (this.closest('[data-draggable-zone]') !== dragState.zone) {
    return;
  }
  event.preventDefault();
  const rect = this.getBoundingClientRect();
  const shouldInsertBefore = (event.clientY - rect.top) < rect.height / 2;
  this.classList.toggle('card-drop-before', shouldInsertBefore);
  this.classList.toggle('card-drop-after', !shouldInsertBefore);
};

const handleCardDragLeave = function () {
  this.classList.remove('card-drop-before', 'card-drop-after');
};

const handleCardDrop = function (event) {
  if (!dragState.card || dragState.card === this) {
    return;
  }
  if (this.closest('[data-draggable-zone]') !== dragState.zone) {
    return;
  }
  event.preventDefault();
  const rect = this.getBoundingClientRect();
  const shouldInsertBefore = (event.clientY - rect.top) < rect.height / 2;
  const parent = dragState.zone;
  if (shouldInsertBefore) {
    parent.insertBefore(dragState.card, this);
  } else {
    parent.insertBefore(dragState.card, this.nextSibling);
  }
  handleCardDragLeave.call(this);
};

const initCardDragAndDrop = () => {
  const zones = document.querySelectorAll('[data-draggable-zone]');
  if (!zones.length) {
    return;
  }

  zones.forEach((zone) => {
    zone.addEventListener('dragover', (event) => {
      if (!dragState.card || dragState.zone !== zone) {
        return;
      }
      event.preventDefault();
    });
    zone.addEventListener('drop', (event) => {
      if (!dragState.card || dragState.zone !== zone) {
        return;
      }
      event.preventDefault();
      clearDropIndicators();
      const targetCard = event.target.closest('.card');
      if (!targetCard) {
        zone.appendChild(dragState.card);
      }
    });
  });

  const cards = document.querySelectorAll('[data-draggable-zone] .card');
  cards.forEach((card) => {
    if (card.dataset.dragEnabled === "1") {
      return;
    }
    card.dataset.dragEnabled = "1";
    card.setAttribute('draggable', 'true');
    card.addEventListener('dragstart', handleCardDragStart);
    card.addEventListener('dragend', handleCardDragEnd);
    card.addEventListener('dragover', handleCardDragOver);
    card.addEventListener('dragleave', handleCardDragLeave);
    card.addEventListener('drop', handleCardDrop);
  });
};

initCardDragAndDrop();
