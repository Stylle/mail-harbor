import { writeFile } from 'node:fs/promises';
await writeFile(new URL('../../web/.keep',import.meta.url),'');
