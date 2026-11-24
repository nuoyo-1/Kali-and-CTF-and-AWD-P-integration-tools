"""Small bounded operations run inside the selected project's Python venv."""
import json
from pathlib import Path
import re
import sys
import time

def address(value, optional=False):
    if optional and not value:return None
    if not re.fullmatch(r'(?:0[xX][0-9a-fA-F]{1,16}|[0-9]{1,20})',value):
        raise ValueError('地址须为十进制数字或 0x 开头的十六进制数字')
    result=int(value,16 if value.lower().startswith('0x') else 10)
    if not 0<result<2**64:raise ValueError('地址必须大于0且小于2^64')
    return result

def settings(find,avoid,length,printable):
    goal=address(find);skip=address(avoid,True)
    if not re.fullmatch(r'[0-9]{1,3}',length) or not 1<=int(length)<=256:
        raise ValueError('符号输入长度须为1～256字节')
    if printable not in ('yes','no'):raise ValueError('ASCII 选项无效')
    if goal==skip:raise ValueError('成功地址与失败地址不能相同')
    return goal,skip,int(length),printable=='yes'

def angr_find(file,find,avoid,length,printable):
    goal,skip,size,ascii_only=settings(find,avoid,length,printable)
    with Path(file).open('rb') as stream:
        if stream.read(4)!=b'\x7fELF':raise ValueError('此预设仅针对 ELF；其他格式请使用专用分析环境')
    import angr
    # angr 10 vendors claripy; it no longer installs a top-level claripy module.
    from angr import claripy
    project=angr.Project(file,auto_load_libs=False)
    for a in (goal,skip):
        if a is not None and not project.loader.find_object_containing(a):
            raise ValueError('地址不在 angr 映射范围内，请检查 PIE 基址和地址，不要使用文件偏移')
    symbol=claripy.BVS('ctf_input',size*8)
    state=project.factory.full_init_state(stdin=angr.SimFileStream(name='stdin',content=symbol,has_end=True))
    state.solver._solver.timeout=5000
    if ascii_only:
        for byte in symbol.chop(8):state.solver.add(byte>=0x20,byte<=0x7e)
    manager=project.factory.simgr(state)
    manager.use_technique(angr.exploration_techniques.Explorer(find=goal,avoid=[] if skip is None else [skip]))
    start=time.monotonic();reason='达到3000步限制'
    print(f'开始分析；主模块基址 {project.loader.main_object.mapped_base:#x}，目标 {goal:#x}，输入 {size} 字节',flush=True)
    for step in range(3000):
        if time.monotonic()-start>=90:reason='达到90秒限制';break
        if len(manager.active)>1024:reason='活动状态超过1024个，已停止';break
        if not manager.active:reason='没有更多可探索状态';break
        manager.step()
        if manager.found:
            candidate=manager.found[0].solver.eval(symbol,cast_to=bytes)
            Path('candidate.bin').write_bytes(candidate)
            result=dict(found=True,target=hex(goal),hex=candidate.hex(),text=candidate.decode('utf-8',errors='replace'),steps=step+1)
            Path('candidate.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
            print('找到本模型下的候选输入：'+repr(candidate)+'；请结合程序实际逻辑验证。',flush=True)
            return
        if step%100==0:print(f'已执行 {step+1} 步；活动状态 {len(manager.active)}',flush=True)
    result=dict(found=False,reason=reason,errors=len(manager.errored))
    Path('analysis.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    print('本次没有找到候选：'+reason+'。这不能证明题目无解。',flush=True)
    if manager.errored:print('部分路径发生模拟错误：'+str(manager.errored[0].error),flush=True)

if __name__=='__main__':
    try:
        if len(sys.argv)!=7 or sys.argv[1]!='angr-find':raise ValueError('未登记的运行任务')
        angr_find(*sys.argv[2:])
    except Exception as error:
        print('分析失败：'+str(error),flush=True)
        sys.exit(1)
