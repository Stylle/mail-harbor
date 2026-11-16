import { ref } from "vue";
import { en } from "./translations";
export const language = ref<"zh" | "en">("zh");
try {
  if (localStorage.getItem("mail-harbor.language") === "en")
    language.value = "en";
} catch {}
function applyLanguage() {
  if (typeof document === "undefined") return;
  document.documentElement.lang = language.value === "zh" ? "zh-CN" : "en";
  document.title =
    language.value === "zh" ? "邮屿 · Mail Harbor" : "Mail Harbor";
}
applyLanguage();
export function toggleLanguage() {
  language.value = language.value === "zh" ? "en" : "zh";
  applyLanguage();
  try {
    localStorage.setItem("mail-harbor.language", language.value);
  } catch {}
}
export function t(text: string) {
  return language.value === "en" ? en[text] || text : text;
}
