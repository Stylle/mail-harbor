<script setup lang="ts">
import { ref } from "vue";
import { t } from "./i18n";
const props = defineProps<{
  api: (path: string, data?: any) => Promise<any>;
  needsPasswordChange: boolean;
  replacing?: boolean;
}>();
const emit = defineEmits<{ done: [result: any] }>();
const step = ref<"start" | "verify" | "recovery">("start"),
  current = ref(""),
  oldCode = ref(""),
  password = ref(""),
  repeat = ref(""),
  code = ref(""),
  qr = ref(""),
  secret = ref(""),
  error = ref(""),
  working = ref(false),
  codes = ref<string[]>([]),
  result = ref<any>(null);
async function begin() {
  working.value = true;
  error.value = "";
  try {
    const r = await props.api("2fa/begin", {
      current: current.value,
      code: oldCode.value,
    });
    qr.value = "data:image/png;base64," + r.qr;
    secret.value = r.secret;
    current.value = "";
    oldCode.value = "";
    step.value = "verify";
  } catch (e) {
    error.value = e instanceof Error ? t(e.message) : t("操作失败");
  } finally {
    working.value = false;
  }
}
async function confirm() {
  if (password.value !== repeat.value) {
    error.value = t("两次密码不一致");
    return;
  }
  working.value = true;
  error.value = "";
  try {
    result.value = await props.api("2fa/confirm", {
      code: code.value,
      password: password.value,
    });
    qr.value = "";
    secret.value = "";
    password.value = "";
    repeat.value = "";
    code.value = "";
    codes.value = result.value.recoveryCodes;
    step.value = "recovery";
  } catch (e) {
    error.value = e instanceof Error ? t(e.message) : t("操作失败");
  } finally {
    working.value = false;
  }
}
async function copyCodes() {
  try {
    await navigator.clipboard.writeText(codes.value.join("\n"));
  } catch {
    error.value = t("复制失败，请手动选择恢复码复制");
  }
}
</script>
<template>
  <section class="enroll-card">
    <h1>{{ replacing ? t("更换验证器") : t("设置双重验证") }}</h1>
    <p>
      {{
        replacing
          ? t("验证当前密码和验证码后，绑定新的验证器。")
          : t(
              "绑定验证器后才能进入邮箱。支持 Google Authenticator、Microsoft Authenticator 等 TOTP 应用。",
            )
      }}
    </p>
    <form v-if="step === 'start'" @submit.prevent="begin">
      <template v-if="replacing"
        ><label
          >{{ t("当前密码")
          }}<input
            v-model="current"
            type="password"
            autocomplete="current-password"
            required /></label
        ><label
          >{{ t("当前验证码")
          }}<input
            v-model="oldCode"
            inputmode="numeric"
            autocomplete="one-time-code"
            pattern="[0-9]{6}"
            maxlength="6"
            required /></label></template
      ><button class="primary" :disabled="working">{{ t("开始绑定") }}</button>
    </form>
    <form v-else-if="step === 'verify'" @submit.prevent="confirm">
      <div class="qr-enrollment">
        <img :src="qr" :alt="t('验证器绑定二维码')" width="220" height="220" />
        <details>
          <summary>{{ t("无法扫码？手动输入密钥") }}</summary>
          <code>{{ secret }}</code>
        </details>
      </div>
      <template v-if="needsPasswordChange"
        ><label
          >{{ t("设置强密码")
          }}<input
            v-model="password"
            type="password"
            autocomplete="new-password"
            minlength="12"
            maxlength="256"
            required
        /></label>
        <p class="field-help">
          {{ t("至少12个字符，包含大写字母、小写字母、数字和符号。") }}
        </p>
        <label
          >{{ t("确认新密码")
          }}<input
            v-model="repeat"
            type="password"
            autocomplete="new-password"
            required /></label></template
      ><label
        >{{ t("验证器验证码")
        }}<input
          v-model="code"
          inputmode="numeric"
          autocomplete="one-time-code"
          maxlength="6"
          pattern="[0-9]{6}"
          required /></label
      ><button class="primary" :disabled="working">
        {{ t("确认并启用") }}
      </button>
    </form>
    <div v-else>
      <h2>{{ t("保存恢复码") }}</h2>
      <p>
        {{
          t(
            "丢失验证器时，可用管理密码和一个恢复码重新绑定。每个恢复码只能使用一次，仅显示本次。",
          )
        }}
      </p>
      <div class="recovery-codes">
        <code v-for="recovery in codes" :key="recovery">{{ recovery }}</code>
      </div>
      <div class="button-row">
        <button @click="copyCodes">{{ t("复制恢复码") }}</button
        ><button
          class="primary"
          @click="
            emit('done', result);
            codes = [];
          "
        >
          {{ t("继续进入邮箱") }}
        </button>
      </div>
    </div>
    <p v-if="error" class="inline-error" role="alert">{{ error }}</p>
  </section>
</template>
