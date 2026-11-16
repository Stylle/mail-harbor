import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {parseLinks} from '../src/links.ts';
import {en} from '../src/translations.ts';

test('links preserve mail text and separate punctuation without interpreting HTML',()=>{
 const text='说明 https://example.org/report?a=1&b=2。\n联系 team@example.org，访问 www.example.org/docs(test)。';
 const parts=parseLinks(text);assert.equal(parts.map(p=>p.text).join(''),text);const links=parts.filter(p=>p.href);assert.equal(links.length,3);assert.equal(links[0].href,'https://example.org/report?a=1&b=2');assert.equal(links[1].href,'mailto:team@example.org');assert.equal(links[2].href,'https://www.example.org/docs(test)');
});
test('dangerous schemes, credential URLs and embedded scheme tricks remain inert',()=>{for(const text of ['javascript:alert(1)','data:text/html,<script>alert(1)</script>','file:///etc/passwd','javascript:https://example.org','https://user:password@example.org'])assert.equal(parseLinks(text).filter(p=>p.href).length,0)});
test('mail markup remains literal and recognition has a bounded link count',()=>{const text='<img src=x onerror=alert(1)> '+Array.from({length:300},(_,i)=>'https://example.org/'+i).join(' ');const parts=parseLinks(text);assert.equal(parts.map(p=>p.text).join(''),text);assert.equal(parts.filter(p=>p.href).length,128)});
test('static translated UI labels have English equivalents',async()=>{const missing=new Set();for(const name of ['App','ComposeMail','SecurityEnroll']){const source=await readFile(new URL('../src/'+name+'.vue',import.meta.url),'utf8');for(const match of source.matchAll(/\bt\(\s*("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')/g)){const raw=match[1];const key=raw[0]==='"'?JSON.parse(raw):raw.slice(1,-1).replace(/\\'/g,"'").replace(/\\n/g,'\n').replace(/\\\\/g,'\\');if(/[\u3400-\u9fff]/.test(key)&&!en[key])missing.add(key)}}assert.deepEqual([...missing],[])});
