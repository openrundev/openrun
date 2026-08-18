// jsonTreeSetAll expands or collapses every JSON tree in the result card
// holding the clicked button. Collapse keeps the root node expanded, so the
// tree folds down to its first level (the default render state)
function jsonTreeSetAll(btn, expand) {
    const scope = btn.closest('.card') || document;
    scope.querySelectorAll('.json-container').forEach((container) => {
      container.querySelectorAll('.json-tree li').forEach((li) => {
        const arrow = li.querySelector(':scope > .arrow');
        if (!arrow || li.classList.contains('leaf')) {
          return; // leaf or plain text node, nothing to toggle
        }
        const open = expand || li.classList.contains('root');
        li.classList.toggle('collapsed', !open);
        li.classList.toggle('expanded', open);
        arrow.textContent = open ? '▼' : '▶';
      });
    });
  }

  function renderJSON(json, container, level = 0) {
    const ul = document.createElement('ul');
    ul.classList.add('json-tree');

    if (typeof json === 'object' && json !== null) {
      const isArray = Array.isArray(json);
      const entries = isArray ? json : Object.entries(json);

      entries.forEach((item, index) => {
        const li = document.createElement('li');
        let key, value;

        if (isArray) {
          key = index;
          value = item;
        } else {
          [key, value] = item;
        }

        // Create arrow span
        const arrowSpan = document.createElement('span');
        arrowSpan.classList.add('arrow');

        const keySpan = document.createElement('span');
        keySpan.classList.add('json-key', 'key');
        keySpan.textContent = isArray ? `[${key}]` : key;

        if (typeof value === 'object' && value !== null) {
          li.classList.add('collapsed');
          arrowSpan.textContent = '▶';

          arrowSpan.addEventListener('click', (e) => {
            e.stopPropagation();
            li.classList.toggle('collapsed');
            li.classList.toggle('expanded');
            // Update arrow
            arrowSpan.textContent = li.classList.contains('collapsed') ? '▶' : '▼';
          });

          keySpan.addEventListener('click', (e) => {
            e.stopPropagation();
            li.classList.toggle('collapsed');
            li.classList.toggle('expanded');
            // Update arrow
            arrowSpan.textContent = li.classList.contains('collapsed') ? '▶' : '▼';
          });

          li.appendChild(arrowSpan);
          li.appendChild(keySpan);

          renderJSON(value, li, level + 1);
        } else {
          li.classList.add('leaf');
          // Empty arrow span to align with other items
          const emptyArrowSpan = document.createElement('span');
          emptyArrowSpan.classList.add('arrow');
          emptyArrowSpan.textContent = '';
          li.appendChild(emptyArrowSpan);
          li.appendChild(keySpan);

          const separator = document.createTextNode(': ');
          const valueSpan = document.createElement('span');
          valueSpan.classList.add('json-value');

          if (typeof value === 'string') {
            valueSpan.classList.add('json-string');
            valueSpan.textContent = `"${value}"`;
          } else if (typeof value === 'number') {
            valueSpan.classList.add('json-number');
            valueSpan.textContent = value;
          } else if (typeof value === 'boolean') {
            valueSpan.classList.add('json-boolean');
            valueSpan.textContent = value;
          } else if (value === null) {
            valueSpan.classList.add('json-null');
            valueSpan.textContent = 'null';
          } else {
            valueSpan.textContent = value;
          }

          li.appendChild(separator);
          li.appendChild(valueSpan);
        }

        ul.appendChild(li);
      });
    } else {
      const li = document.createElement('li');
      li.textContent = json;
      ul.appendChild(li);
    }

    container.appendChild(ul);
  }

  // Function to wrap the JSON data under a root node
  function renderJSONWithRoot(json, container) {
    const rootUl = document.createElement('ul');
    rootUl.classList.add('json-tree');

    const rootLi = document.createElement('li');
    rootLi.classList.add('expanded', 'root'); // Add 'root' class

    const arrowSpan = document.createElement('span');
    arrowSpan.classList.add('arrow');
    arrowSpan.textContent = '▼';

    const keySpan = document.createElement('span');
    keySpan.classList.add('json-key', 'key');
    keySpan.textContent = 'root';

    arrowSpan.addEventListener('click', (e) => {
      e.stopPropagation();
      rootLi.classList.toggle('collapsed');
      rootLi.classList.toggle('expanded');
      // Update arrow
      arrowSpan.textContent = rootLi.classList.contains('collapsed') ? '▶' : '▼';
    });

    keySpan.addEventListener('click', (e) => {
      e.stopPropagation();
      rootLi.classList.toggle('collapsed');
      rootLi.classList.toggle('expanded');
      // Update arrow
      arrowSpan.textContent = rootLi.classList.contains('collapsed') ? '▶' : '▼';
    });

    rootLi.appendChild(arrowSpan);
    rootLi.appendChild(keySpan);

    renderJSON(json, rootLi, 1);

    rootUl.appendChild(rootLi);
    container.appendChild(rootUl);
  }