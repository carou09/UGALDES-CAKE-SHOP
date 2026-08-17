(() => {
  const snapshots = new WeakMap();

  const editableFields = row => [...row.querySelectorAll('input[form], textarea[form], select[form]')];

  const syncClientEmail = row => {
    const checkbox = row.querySelector('[data-no-client-email]');
    const email = row.querySelector('[data-client-email]');
    if (!checkbox || !email) return;
    const editing = row.classList.contains('is-editing');
    checkbox.disabled = !editing;
    email.disabled = !editing || checkbox.checked;
    email.required = editing && !checkbox.checked;
    email.placeholder = checkbox.checked ? 'No Aplica' : 'Correo electrónico';
    if (checkbox.checked) email.value = '';
  };

  const beginEditing = (row, button) => {
    const fields = editableFields(row);
    snapshots.set(row, fields.map(field => ({
      field,
      value: field.value,
      checked: field.matches('[type="checkbox"], [type="radio"]') ? field.checked : undefined
    })));
    row.classList.add('is-editing');
    fields.forEach(field => { field.disabled = false; });
    syncClientEmail(row);
    row.querySelectorAll('textarea').forEach(textarea => {
      textarea.style.height = 'auto';
      textarea.style.height = `${textarea.scrollHeight}px`;
    });
    button.dataset.editLabel ||= button.textContent;
    button.textContent = 'Guardar cambios';
    button.classList.replace('btn-secondary','btn-primary');
    const cancel = row.querySelector('[data-cancel-edit]');
    if (cancel) cancel.hidden = false;
    fields.find(field => !field.disabled)?.focus();
  };

  const cancelEditing = row => {
    const snapshot = snapshots.get(row) || [];
    snapshot.forEach(({field,value,checked}) => {
      field.value = value;
      if (checked !== undefined) field.checked = checked;
      field.disabled = true;
    });
    row.classList.remove('is-editing');
    syncClientEmail(row);
    const button = row.querySelector('[data-edit-button]');
    if (button) {
      button.textContent = button.dataset.editLabel || 'Editar';
      button.classList.replace('btn-primary','btn-secondary');
      button.focus();
    }
    const cancel = row.querySelector('[data-cancel-edit]');
    if (cancel) cancel.hidden = true;
    snapshots.delete(row);
  };

  document.addEventListener('click', event => {
    const editButton = event.target.closest('[data-edit-button]');
    const cancelButton = event.target.closest('[data-cancel-edit]');
    if (!editButton && !cancelButton) return;
    event.preventDefault();
    event.stopImmediatePropagation();
    const row = (editButton || cancelButton).closest('[data-edit-row]');
    if (!row) return;
    if (cancelButton) return cancelEditing(row);
    if (row.classList.contains('is-editing')) return editButton.form.requestSubmit();
    beginEditing(row,editButton);
  },true);

  document.addEventListener('change', event => {
    if (event.target.matches('[data-no-client-email]')) syncClientEmail(event.target.closest('[data-edit-row]'));
  });
})();
