<script setup lang="ts">
import { ref, reactive } from "vue";
import { PhPaperPlaneTilt, PhX, PhPaperclip } from "@phosphor-icons/vue";
import { t } from "./i18n";
const props = defineProps<{
  accounts: {
    id: string;
    name: string;
    email: string;
    provider: string;
    authorized: boolean;
  }[];
  api: (path: string, data?: any) => Promise<any>;
  reply?: { accountId: string; sender: string; subject: string };
}>();
const emit = defineEmits<{ close: []; sent: [] }>();
const id = () =>
  Array.from(crypto.getRandomValues(new Uint8Array(20)), (b) =>
    b.toString(16).padStart(2, "0"),
  ).join("");
const draft = reactive({
  id: id(),
  accountId:
    props.reply?.accountId ||
    props.accounts.find((a) => a.authorized)?.id ||
    "",
  to: props.reply?.sender || "",
  cc: "",
  bcc: "",
  subject: props.reply
    ? /^re:/i.test(props.reply.subject)
      ? props.reply.subject
      : "Re: " + props.reply.subject
    : "",
  text: "",
  attachments: [] as { name: string; contentType: string; data: string }[],
});
const busy = ref(false),
  error = ref(""),
  files = ref<HTMLInputElement>(),
  extra = ref(false);
async function addFiles(event: Event) {
  const selected = (event.target as HTMLInputElement).files;
  if (!selected) return;
  error.value = "";
  let size = draft.attachments.reduce((n, a) => n + a.data.length * 0.75, 0);
  for (const file of selected) {
    size += file.size;
    if (size > 8 * 1024 * 1024 || draft.attachments.length >= 10) {
      error.value = t("最多10个附件，合计不能超过8MB");
      break;
    }
    const data = await new Promise<string>((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(String(reader.result).split(",")[1]);
      reader.onerror = () => reject(Error(t("附件读取失败")));
      reader.readAsDataURL(file);
    });
    draft.attachments.push({
      name: file.name,
      contentType: file.type || "application/octet-stream",
      data,
    });
  }
  (event.target as HTMLInputElement).value = "";
}
async function send() {
  if (busy.value) return;
  busy.value = true;
  error.value = "";
  try {
    const r = await props.api("send", { ...draft });
    if (r.status === "accepted") {
      emit("sent");
      emit("close");
    } else error.value = t("该请求已处理，请查看发信记录；请勿重复点击发送");
  } catch (e) {
    error.value = e instanceof Error ? t(e.message) : t("发送失败");
  } finally {
    busy.value = false;
  }
}
function close() {
  if (busy.value) return;
  if (
    (draft.text || draft.subject) &&
    !confirm(t("关闭后将丢弃当前草稿，确认继续？"))
  )
    return;
  emit("close");
}
</script>
<template>
  <div class="compose-overlay" @click.self="close">
    <section
      class="compose-panel"
      role="dialog"
      aria-modal="true"
      :aria-label="t('写邮件')"
    >
      <header>
        <h2>{{ t("新邮件") }}</h2>
        <button
          class="icon-button"
          :aria-label="t('关闭写信')"
          :disabled="busy"
          @click="close"
        >
          <PhX :size="21" />
        </button>
      </header>
      <form @submit.prevent="send">
        <label
          >{{ t("发件邮箱")
          }}<select
            v-model="draft.accountId"
            :aria-label="t('发件邮箱')"
            required
          >
            <option
              v-for="a in accounts"
              :key="a.id"
              :disabled="!a.authorized"
              :value="a.id"
            >
              {{ a.name }} · {{ a.email }}
            </option>
          </select></label
        ><label
          >{{ t("收件人")
          }}<input
            v-model="draft.to"
            required
            :placeholder="t('name@example.com，多个地址用逗号分隔')"
            maxlength="8000" /></label
        ><button type="button" class="text-button" @click="extra = !extra">
          {{ t("抄送 / 密送") }}
        </button>
        <div v-if="extra" class="form-grid">
          <label
            >{{ t("抄送") }}<input v-model="draft.cc" maxlength="8000" /></label
          ><label
            >{{ t("密送") }}<input v-model="draft.bcc" maxlength="8000"
          /></label>
        </div>
        <label
          >{{ t("主题")
          }}<input v-model="draft.subject" maxlength="1000" /></label
        ><label
          >{{ t("正文")
          }}<textarea
            v-model="draft.text"
            rows="10"
            required
            maxlength="1000000"
            :placeholder="t('撰写邮件…')"
          ></textarea></label
        ><input
          ref="files"
          type="file"
          multiple
          class="hidden-file"
          @change="addFiles"
        />
        <div class="compose-attachments">
          <div v-for="(file, index) in draft.attachments" :key="index">
            <PhPaperclip :size="16" /><span>{{ file.name }}</span
            ><button
              type="button"
              class="icon-button"
              :aria-label="t('移除附件')"
              @click="draft.attachments.splice(index, 1)"
            >
              <PhX :size="14" />
            </button>
          </div>
        </div>
        <p v-if="error" class="inline-error" role="alert">{{ error }}</p>
        <footer>
          <button type="button" :disabled="busy" @click="files?.click()">
            <PhPaperclip :size="18" />{{ t("添加附件") }}</button
          ><small>{{ t("Outlook 附件合计最多2MB，其他邮箱8MB。") }}</small
          ><button class="primary" :disabled="busy || !draft.accountId">
            <PhPaperPlaneTilt :size="18" />{{
              busy ? t("正在提交…") : t("发送")
            }}
          </button>
        </footer>
      </form>
    </section>
  </div>
</template>
