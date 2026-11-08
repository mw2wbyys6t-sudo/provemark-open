import moment from "moment";

export function formatMoney(value) {
  return `$${Number(value || 0).toFixed(2)}`;
}

export function formatDate(value) {
  return moment(value).format("YYYY-MM-DD HH:mm");
}

export function renderNote(text) {
  const node = document.createElement("div");
  node.innerHTML = text;
  return node;
}
