import { useEffect, useMemo, useRef, useState } from "react";
import { fetchSharedClientState, saveSharedClientState } from "../services/api";
import { getAuthToken } from "../services/authSession";

const RECOVERY_STATE_PREFIX = "blockgo:recovery:state:";
const FIELD_DRAFTS_KEY = "blockgo:recovery:fieldDrafts";
const SHARED_RECOVERY_KEY = "sessionRecoveryDrafts";
const FIELD_DRAFT_TTL_MS = 1000 * 60 * 60 * 24 * 7;
const SHARED_SYNC_DELAY_MS = 700;

let sharedRecoveryCache = null;
let sharedHydratePromise = null;
let sharedSyncTimer = null;

const safeParse = (rawValue, fallback) => {
  try {
    return rawValue ? JSON.parse(rawValue) : fallback;
  } catch {
    return fallback;
  }
};

const getStorageScope = () => {
  const token = getAuthToken();
  if (!token) return "guest";

  try {
    const payload = JSON.parse(atob(token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
    return (
      payload.username ||
      payload.email ||
      payload["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"] ||
      "authenticated"
    );
  } catch {
    return "authenticated";
  }
};

const buildStateKey = (key, scope = getStorageScope()) => `${RECOVERY_STATE_PREFIX}${scope}:${key}`;

const normalizeDraftPart = (part) => String(part || "").trim().toLowerCase().replace(/\s+/g, "_");

const getUpdatedTime = (entry) => {
  const time = entry?.updatedAt ? new Date(entry.updatedAt).getTime() : 0;
  return Number.isFinite(time) ? time : 0;
};

const hasSharedRecoveryAuth = () => Boolean(getAuthToken());

const normalizeSharedRecovery = (value) =>
  value && typeof value === "object" && !Array.isArray(value) ? value : {};

const getFieldDrafts = () => {
  const drafts = safeParse(localStorage.getItem(FIELD_DRAFTS_KEY), {});
  const now = Date.now();
  let changed = false;

  Object.entries(drafts).forEach(([key, draft]) => {
    if (!draft?.updatedAt || now - new Date(draft.updatedAt).getTime() > FIELD_DRAFT_TTL_MS) {
      delete drafts[key];
      changed = true;
    }
  });

  if (changed) localStorage.setItem(FIELD_DRAFTS_KEY, JSON.stringify(drafts));
  return drafts;
};

const listRecoveredStatesForScope = (scope = getStorageScope()) => {
  const prefix = `${RECOVERY_STATE_PREFIX}${scope}:`;
  return Object.keys(localStorage).reduce((states, storageKey) => {
    if (!storageKey.startsWith(prefix)) return states;
    const entry = safeParse(localStorage.getItem(storageKey), null);
    if (entry && Object.prototype.hasOwnProperty.call(entry, "value")) {
      states[storageKey.slice(prefix.length)] = entry;
    }
    return states;
  }, {});
};

const writeRecoveredStatesForScope = (states, scope = getStorageScope()) => {
  Object.entries(states || {}).forEach(([stateKey, remoteEntry]) => {
    if (!remoteEntry || !Object.prototype.hasOwnProperty.call(remoteEntry, "value")) return;
    const localKey = buildStateKey(stateKey, scope);
    const localEntry = safeParse(localStorage.getItem(localKey), null);
    if (getUpdatedTime(remoteEntry) >= getUpdatedTime(localEntry)) {
      localStorage.setItem(localKey, JSON.stringify(remoteEntry));
    }
  });
};

const getScopedFieldDrafts = (scope = getStorageScope()) => {
  const prefix = `${normalizeDraftPart(scope)}|`;
  return Object.entries(getFieldDrafts()).reduce((drafts, [draftKey, draft]) => {
    if (draftKey.startsWith(prefix)) drafts[draftKey] = draft;
    return drafts;
  }, {});
};

const mergeFieldDrafts = (remoteDrafts = {}) => {
  const localDrafts = getFieldDrafts();
  const mergedDrafts = { ...localDrafts };

  Object.entries(remoteDrafts).forEach(([draftKey, remoteDraft]) => {
    if (getUpdatedTime(remoteDraft) >= getUpdatedTime(localDrafts[draftKey])) {
      mergedDrafts[draftKey] = remoteDraft;
    }
  });

  localStorage.setItem(FIELD_DRAFTS_KEY, JSON.stringify(mergedDrafts));
  return mergedDrafts;
};

const getCurrentScopeRecoveryPayload = (scope = getStorageScope()) => ({
  states: listRecoveredStatesForScope(scope),
  fields: getScopedFieldDrafts(scope),
  updatedAt: new Date().toISOString(),
});

const hydrateSharedRecovery = async () => {
  if (!hasSharedRecoveryAuth()) return null;
  if (sharedHydratePromise) return sharedHydratePromise;

  sharedHydratePromise = (async () => {
    const response = await fetchSharedClientState(SHARED_RECOVERY_KEY);
    const sharedRecovery = normalizeSharedRecovery(response?.value);
    const scope = getStorageScope();
    const remoteScopeRecovery = normalizeSharedRecovery(sharedRecovery[scope]);

    sharedRecoveryCache = sharedRecovery;
    writeRecoveredStatesForScope(remoteScopeRecovery.states, scope);
    mergeFieldDrafts(remoteScopeRecovery.fields);
    return remoteScopeRecovery;
  })()
    .catch((error) => {
      console.warn("[SessionRecovery] Shared recovery hydrate failed:", error.message);
      return null;
    })
    .finally(() => {
      sharedHydratePromise = null;
    });

  return sharedHydratePromise;
};

const syncSharedRecoveryNow = async () => {
  if (!hasSharedRecoveryAuth()) return;

  const response = await fetchSharedClientState(SHARED_RECOVERY_KEY).catch(() => null);
  const sharedRecovery = normalizeSharedRecovery(response?.value || sharedRecoveryCache);
  const scope = getStorageScope();

  sharedRecovery[scope] = getCurrentScopeRecoveryPayload(scope);
  sharedRecoveryCache = sharedRecovery;
  await saveSharedClientState(SHARED_RECOVERY_KEY, sharedRecovery);
};

const scheduleSharedRecoverySync = () => {
  if (!hasSharedRecoveryAuth()) return;
  if (sharedSyncTimer) window.clearTimeout(sharedSyncTimer);

  sharedSyncTimer = window.setTimeout(() => {
    syncSharedRecoveryNow().catch((error) => {
      console.warn("[SessionRecovery] Shared recovery sync failed:", error.message);
    });
  }, SHARED_SYNC_DELAY_MS);
};

const flushSharedRecovery = () => {
  if (sharedSyncTimer) window.clearTimeout(sharedSyncTimer);
  sharedSyncTimer = null;
  syncSharedRecoveryNow().catch((error) => {
    console.warn("[SessionRecovery] Shared recovery flush failed:", error.message);
  });
};

const removeSharedRecoveryScope = async (scope) => {
  if (!hasSharedRecoveryAuth()) return;

  const response = await fetchSharedClientState(SHARED_RECOVERY_KEY).catch(() => null);
  const sharedRecovery = normalizeSharedRecovery(response?.value || sharedRecoveryCache);
  delete sharedRecovery[scope];
  sharedRecoveryCache = sharedRecovery;
  await saveSharedClientState(SHARED_RECOVERY_KEY, sharedRecovery);
};

export const readRecoveredState = (key, fallback) => {
  const saved = safeParse(localStorage.getItem(buildStateKey(key)), null);
  return saved && Object.prototype.hasOwnProperty.call(saved, "value") ? saved.value : fallback;
};

export const writeRecoveredState = (key, value, options = {}) => {
  localStorage.setItem(
    buildStateKey(key),
    JSON.stringify({ value, updatedAt: new Date().toISOString() })
  );
  if (options.sync !== false) scheduleSharedRecoverySync();
};

export const removeRecoveredState = (key) => {
  localStorage.removeItem(buildStateKey(key));
  scheduleSharedRecoverySync();
};

export const useRecoveredState = (key, initialValue) => {
  const initialValueRef = useRef(initialValue);
  const sharedHydratedRef = useRef(!hasSharedRecoveryAuth());
  const resolvedInitialValue = useMemo(() => readRecoveredState(key, initialValue), [key]);
  const [value, setValue] = useState(resolvedInitialValue);

  useEffect(() => {
    initialValueRef.current = initialValue;
  }, [initialValue]);

  useEffect(() => {
    let cancelled = false;
    sharedHydratedRef.current = !hasSharedRecoveryAuth();

    hydrateSharedRecovery()
      .then(() => {
        if (cancelled) return;
        setValue(readRecoveredState(key, initialValueRef.current));
      })
      .finally(() => {
        if (cancelled) return;
        sharedHydratedRef.current = true;
        scheduleSharedRecoverySync();
      });

    return () => {
      cancelled = true;
    };
  }, [key]);

  useEffect(() => {
    writeRecoveredState(key, value, { sync: sharedHydratedRef.current });
  }, [key, value]);

  return [value, setValue];
};

const getElementDraftKey = (element) => {
  if (!element || !["INPUT", "TEXTAREA", "SELECT"].includes(element.tagName)) return "";

  const type = String(element.type || "").toLowerCase();
  if (["password", "file", "hidden", "submit", "button", "reset"].includes(type)) return "";

  const form = element.closest("form");
  const label =
    element.getAttribute("data-recovery-key") ||
    element.name ||
    element.id ||
    element.getAttribute("aria-label") ||
    element.placeholder ||
    "";
  if (!label) return "";

  const formLabel =
    form?.getAttribute("data-recovery-key") ||
    form?.id ||
    form?.getAttribute("aria-label") ||
    form?.querySelector("h1,h2,h3,h4")?.textContent ||
    "screen";

  return [getStorageScope(), window.location.pathname, formLabel, label]
    .map(normalizeDraftPart)
    .join("|");
};

const readElementValue = (element) => {
  if (element.type === "checkbox" || element.type === "radio") return element.checked;
  return element.value;
};

const writeElementValue = (element, value) => {
  if (element.type === "checkbox" || element.type === "radio") {
    element.checked = !!value;
    element.dispatchEvent(new Event("change", { bubbles: true }));
    return;
  }

  const setter = Object.getOwnPropertyDescriptor(element.constructor.prototype, "value")?.set;
  if (setter) setter.call(element, value ?? "");
  else element.value = value ?? "";
  element.dispatchEvent(new Event("input", { bubbles: true }));
  element.dispatchEvent(new Event("change", { bubbles: true }));
};

export const useSessionRecovery = () => {
  useEffect(() => {
    const saveFieldDraft = (event) => {
      const element = event.target;
      const key = getElementDraftKey(element);
      if (!key) return;

      const drafts = getFieldDrafts();
      drafts[key] = {
        value: readElementValue(element),
        updatedAt: new Date().toISOString(),
      };
      localStorage.setItem(FIELD_DRAFTS_KEY, JSON.stringify(drafts));
      scheduleSharedRecoverySync();
    };

    const restoreFieldDrafts = () => {
      const drafts = getFieldDrafts();
      document.querySelectorAll("input, textarea, select").forEach((element) => {
        const key = getElementDraftKey(element);
        if (!key || !Object.prototype.hasOwnProperty.call(drafts, key)) return;
        const draft = drafts[key];
        if (readElementValue(element) === draft.value) return;
        writeElementValue(element, draft.value);
      });
    };

    const clearSubmittedFormDrafts = (event) => {
      const form = event.target;
      if (!(form instanceof HTMLFormElement)) return;
      const drafts = getFieldDrafts();
      form.querySelectorAll("input, textarea, select").forEach((element) => {
        const key = getElementDraftKey(element);
        if (key) delete drafts[key];
      });
      localStorage.setItem(FIELD_DRAFTS_KEY, JSON.stringify(drafts));
      scheduleSharedRecoverySync();
    };

    const flushWhenHidden = () => {
      if (document.visibilityState === "hidden") flushSharedRecovery();
    };

    hydrateSharedRecovery().finally(restoreFieldDrafts);
    const restoreTimers = [50, 250, 750, 1500].map((delay) =>
      window.setTimeout(restoreFieldDrafts, delay)
    );

    document.addEventListener("input", saveFieldDraft, true);
    document.addEventListener("change", saveFieldDraft, true);
    document.addEventListener("submit", clearSubmittedFormDrafts, true);
    document.addEventListener("visibilitychange", flushWhenHidden);
    window.addEventListener("pageshow", restoreFieldDrafts);
    window.addEventListener("pagehide", flushSharedRecovery);

    return () => {
      restoreTimers.forEach(window.clearTimeout);
      document.removeEventListener("input", saveFieldDraft, true);
      document.removeEventListener("change", saveFieldDraft, true);
      document.removeEventListener("submit", clearSubmittedFormDrafts, true);
      document.removeEventListener("visibilitychange", flushWhenHidden);
      window.removeEventListener("pageshow", restoreFieldDrafts);
      window.removeEventListener("pagehide", flushSharedRecovery);
    };
  }, []);
};

export const clearSessionRecovery = () => {
  const scope = getStorageScope();
  removeSharedRecoveryScope(scope).catch((error) => {
    console.warn("[SessionRecovery] Shared recovery clear failed:", error.message);
  });

  Object.keys(localStorage)
    .filter((key) => key.startsWith(RECOVERY_STATE_PREFIX))
    .forEach((key) => localStorage.removeItem(key));
  localStorage.removeItem(FIELD_DRAFTS_KEY);
};
