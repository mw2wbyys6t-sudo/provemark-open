const TOKEN_KEY = "orderdesk.token";
const DRAFT_KEY = "orderdesk.draft";

export function saveToken(token) {
  localStorage.setItem(TOKEN_KEY, token);
}

export function readToken() {
  return localStorage.getItem(TOKEN_KEY);
}

export function saveDraft(payload) {
  localStorage.setItem(DRAFT_KEY, JSON.stringify(payload));
}

export function readDraft() {
  try {
    return JSON.parse(localStorage.getItem(DRAFT_KEY));
  } catch (error) {
    return null;
  }
}
