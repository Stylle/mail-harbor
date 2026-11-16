<script setup lang="ts">
import { computed } from "vue";
import { parseLinks } from "./links";
const props = defineProps<{ text: string }>();
const parts = computed(() => parseLinks(props.text));
</script>
<template>
  <template v-for="(part, index) in parts" :key="index"
    ><a
      v-if="part.href"
      :href="part.href"
      :target="part.external ? '_blank' : undefined"
      rel="noopener noreferrer nofollow"
      referrerpolicy="no-referrer"
      >{{ part.text }}</a
    ><template v-else>{{ part.text }}</template></template
  >
</template>
