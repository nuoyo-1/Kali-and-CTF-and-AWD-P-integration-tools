'use strict';
let fullInventory=null,fullProgram=null;
const installStates={'program-found':'程序可用','package-only':'软件包已安装，程序入口未找到','unknown':'安装状态未能确认','not-installed':'软件包未安装','reference':'资料或导航条目'};
const officialLabels={'Reconnaissance':'侦察','Resource Development':'资源与开发','Initial Access':'初始访问','Execution':'执行','Persistence':'持久化','Privilege Escalation':'权限提升','Defense Evasion':'防御规避','Credential Access':'凭证访问','Discovery':'发现','Lateral Movement':'横向移动','Collection':'数据收集','Command and Control':'命令与控制','Exfiltration':'数据传出','Impact':'影响','Identify':'识别','Protect':'保护','Detect':'检测','Respond':'响应','Recover':'恢复','Other / Components':'其他工具与组件','Forensics':'数字取证','Services and Other Tools':'服务及其他工具'};
async function openFullCatalog(){
  try{
    fullInventory=await api('/api/inventory');
    const before=document.querySelector('#full-category').value;
    document.querySelector('#full-category').innerHTML='<option value="">全部功能分类</option>'+fullInventory.groups.map(c=>`<option value="${e(c.id)}">${e(c.name)}（${c.count}）</option>`).join('');
    document.querySelector('#full-category').value=before;
    document.querySelector('#full-groups').innerHTML='<button class="group-button" data-full-group="">全部工具 <span>'+fullInventory.total+'</span></button>'+fullInventory.groups.map(g=>`<button class="group-button" data-full-group="${g.id}" title="${e(g.description)}">${e(g.name)} <span>${g.count}</span></button>`).join('');
    document.querySelector('#full-detection').hidden=!fullInventory.detection_error;
    document.querySelector('#full-detection').textContent=fullInventory.detection_error||'';
    document.querySelector('#full-summary').textContent=`官方目录 ${fullInventory.total} 项 · 独立命令 ${fullInventory.unique_binary_count} 个（同名已合并） · 有文档选项的程序 ${fullInventory.form_count} 个。执行结果尚需 Kali 本机验证。`;
    renderFullCatalog();
  }catch(error){toast(error.message);}
}
function renderFullCatalog(){
  if(!fullInventory)return;
  const q=document.querySelector('#full-search').value.toLowerCase().trim(),cat=document.querySelector('#full-category').value,ready=document.querySelector('#full-ready').checked;
  const list=fullInventory.tools.filter(t=>(!cat||t.group===cat)&&(!ready||t.installed)&&(!q||[t.name,t.title_zh,t.group_name,t.description_zh,...t.packages.map(p=>p.name),...t.binaries.map(b=>b.name)].join(' ').toLowerCase().includes(q)));
  document.querySelector('#full-count').textContent=`${list.length} 项`;
  document.querySelectorAll('[data-full-group]').forEach(b=>b.classList.toggle('active',b.dataset.fullGroup===cat));
  const ordered=fullInventory.groups.flatMap(g=>list.filter(t=>t.group===g.id));let last=null;
  document.querySelector('#full-list').innerHTML=ordered.map(t=>{const heading=last!==t.group?`<h2 class="group-heading">${e(t.group_name)}</h2>`:'';last=t.group;return heading+`<article class="full-card"><div class="section-line"><h3><span class="tool-identity">${e(t.name)}</span> <small class="original-name">${e(t.specific_title?t.title_zh:"")}</small></h3><span class="availability ${t.installed?'ready':''}">${e(installStates[t.installation_state]||'状态未知')}</span></div><p class="muted">${e(t.description_zh)} · ${t.binaries.length} 个程序入口</p><div class="full-packages">${t.packages.map(p=>`<button class="secondary" data-full-install="${e(p.id)}">${p.installed?'检查更新':p.detection_known?'安装软件包':'核验软件包并安装'} ${e(p.name)}</button><button class="secondary" data-find-desktop="${e(p.id)}">查找桌面启动图标</button>`).join('')||'<span class="muted">此条目没有独立安装包</span>'}</div><div class="full-binaries">${t.binaries.filter(b=>b.display_primary).map(b=>`<button class="program-button" data-full-program="${e(b.id)}"><span>${e(b.name)}</span><small>${b.installed?'程序已找到':'未找到程序入口'} · ${b.option_count} 项可配置参数 →</small></button>`).join('')||'<p class="muted">没有单独主入口：这是组件/资料，或同名命令已合并到其他工具卡。可管理安装包并查看配置说明。</p>'}</div><a class="card-run" href="${e(t.url)}" target="_blank" rel="noopener noreferrer">官方配置与用法（原文）↗</a>${t.status!=='collected'?'<p class="error">文档未完整收集，不能声称已接入。</p>':''}</article>`}).join('')||'<div class="empty">没有匹配项目。可以搜索中文功能词或原始工具名。</div>';
}
async function openProgram(id){
  try{
    fullProgram=await api('/api/program/'+id);
    document.querySelector('#program-title').textContent=fullProgram.name+' · '+fullProgram.title_zh;
    const item=fullInventory?.tools.flatMap(t=>t.binaries).find(b=>b.id===id);
    const variants=item?.variants||[];const chooser=document.querySelector('#program-variants');chooser.hidden=variants.length<2;
    chooser.innerHTML=variants.length>1?'<label for="program-package-choice">这个命令有多个软件包来源，选择其中一个</label><select id="program-package-choice">'+variants.map(v=>`<option value="${e(v.id)}" ${v.id===id?'selected':''}>${e(v.package)} · ${e(v.source_name)}</option>`).join('')+'</select>':'';
    if(variants.length>1)document.querySelector('#program-package-choice').onchange=event=>openProgram(event.target.value);
    document.querySelector('#program-source').href=fullProgram.source;
    document.querySelector('#program-help').textContent=fullProgram.help||'官方页面没有提供命令帮助。请先查阅官方配置说明。';
    document.querySelector('#program-flag').innerHTML='<option value="">选择需要设置的参数…</option>'+fullProgram.options.map(o=>`<option value="${e(o.flag)}">${e(o.label_zh+' · '+o.flag)}</option>`).join('');
    document.querySelector('#program-elevated').checked=false;document.querySelector('#program-mode').value='batch';document.querySelector('#program-options').innerHTML='';document.querySelector('#program-positions').value='';
    document.querySelector('#program-error').textContent='';document.querySelector('#program-run').disabled=!fullProgram.installed;
    document.querySelector('#program-status').textContent=fullProgram.installed?'本机检测到程序':'请先安装对应软件包';
    document.querySelector('#program-preview').textContent=fullProgram.name;
    document.querySelector('#program-dialog').showModal();
  }catch(error){toast(error.message);}
}
function addProgramOption(){
  const flag=document.querySelector('#program-flag').value;
  const option=fullProgram?.options.find(o=>o.flag===flag);if(!option)return;
  const row=document.createElement('div');row.className='option-row';row.dataset.flag=flag;
  row.innerHTML=`<code>${e(flag)}</code><label><input type="checkbox" class="option-has-value" ${option.takes_value?'checked':''}>需要填写值</label><input type="text" class="option-value" placeholder="参数值 / 文件路径" aria-label="${e(flag)} 参数值"><button type="button" class="secondary option-file">选文件</button><button type="button" class="icon-button option-remove" aria-label="移除选项">×</button><small>${e(option.label_zh)}</small><details><summary>参数原始说明</summary>${e(option.description)}</details>`;
  const picker=document.createElement('input');picker.type='file';picker.hidden=true;row.append(picker);
  picker.addEventListener('change',async()=>{if(!picker.files[0])return;try{const f=picker.files[0];if(f.size>256*1024*1024)throw new Error('文件过大，请填写本机绝对路径');const data=await api('/api/upload?name='+encodeURIComponent(f.name),{method:'POST',body:f});row.querySelector('.option-value').value=data.path;row.querySelector('.option-has-value').checked=true;updatePreview();}catch(error){toast(error.message);}});
  row.querySelector('.option-file').onclick=()=>picker.click();row.querySelector('.option-remove').onclick=()=>{row.remove();updatePreview();};row.addEventListener('input',updatePreview);
  document.querySelector('#program-options').append(row);updatePreview();
}
function programValues(){return {elevated:document.querySelector('#program-elevated').checked,mode:document.querySelector('#program-mode').value,options:[...document.querySelectorAll('.option-row')].map(row=>({flag:row.dataset.flag,value:row.querySelector('.option-has-value').checked?row.querySelector('.option-value').value:null})),positionals:document.querySelector('#program-positions').value.split('\n').filter(x=>x!==''),position_first:document.querySelector('#program-position-first').checked};}
function updatePreview(){if(!fullProgram)return;const v=programValues(),options=v.options.flatMap(o=>o.value===null?[o.flag]:[o.flag,o.value]);const args=v.position_first?[...v.positionals,...options]:[...options,...v.positionals];document.querySelector('#program-preview').textContent=[fullProgram.name,...args].map(x=>JSON.stringify(x)).join(' ');}
async function runProgram(event){event.preventDefault();const run=document.querySelector('#program-run');run.disabled=true;try{const job=await post('/api/run',{tool:fullProgram.id,values:programValues()});document.querySelector('#program-dialog').close();await openJob(job.id);}catch(error){document.querySelector('#program-error').textContent=error.message;}finally{run.disabled=!fullProgram?.installed;}}
async function installFull(id){try{const job=await post('/api/install',{tool:id});await openJob(job.id);}catch(error){toast(error.message);}}
document.addEventListener('click',event=>{const b=event.target.closest('button');if(!b)return;if(b.dataset.view==='catalog')openFullCatalog();if(b.hasAttribute('data-full-group')){document.querySelector('#full-category').value=b.dataset.fullGroup;renderFullCatalog();}if(b.dataset.fullProgram)openProgram(b.dataset.fullProgram);if(b.dataset.fullInstall)installFull(b.dataset.fullInstall);if(b.dataset.findDesktop)findDesktop(b.dataset.findDesktop,b);if(b.dataset.desktopRun)runDesktop(b.dataset.desktopRun);});
document.querySelector('#full-search').addEventListener('input',renderFullCatalog);document.querySelector('#full-category').addEventListener('change',renderFullCatalog);document.querySelector('#full-ready').addEventListener('change',renderFullCatalog);
document.querySelector('#program-add').addEventListener('click',addProgramOption);document.querySelector('#program-form').addEventListener('submit',runProgram);document.querySelector('#program-positions').addEventListener('input',updatePreview);document.querySelector('#program-position-first').addEventListener('change',updatePreview);
document.querySelector('#job-input-form').addEventListener('submit',async event=>{event.preventDefault();try{await post('/api/input',{id:activeJob,text:document.querySelector('#job-input').value+'\n'});document.querySelector('#job-input').value='';}catch(error){toast(error.message);}});
document.querySelector('#program-pos-file').addEventListener('change',async event=>{const f=event.target.files[0];if(!f)return;try{if(f.size>256*1024*1024)throw new Error('文件过大，请填写本机绝对路径');const data=await api('/api/upload?name='+encodeURIComponent(f.name),{method:'POST',body:f});const input=document.querySelector('#program-positions');input.value+=(input.value?'\n':'')+data.path;updatePreview();}catch(error){toast(error.message);}});
document.querySelector('#main-nav').prepend(document.querySelector('[data-view="catalog"]'));
setView('catalog');openFullCatalog();
document.querySelector('#refresh').addEventListener('click',openFullCatalog);

async function findDesktop(id,button){try{button.disabled=true;const entries=await api('/api/desktops/'+id);for(const entry of entries){const b=document.createElement('button');b.className='secondary';b.dataset.desktopRun=entry.id;b.textContent='打开 '+entry.name;button.parentElement.append(b);}if(!entries.length)toast('没有发现已安装的桌面入口；请确认安装状态或按官方说明初始化服务。');}catch(error){toast(error.message);}finally{button.disabled=false;}}
async function runDesktop(id){try{const job=await post('/api/run',{tool:id,values:{}});await openJob(job.id);}catch(error){toast(error.message);}}
