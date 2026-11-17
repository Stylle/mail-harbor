"""Isolated Docker storage regression. Never mounts existing/business data."""
import argparse, json, subprocess, uuid
p=argparse.ArgumentParser();p.add_argument('--image',required=True);p.add_argument('--platform',default='linux/amd64');a=p.parse_args()
prefix='mail-storage-qa-'+uuid.uuid4().hex[:10];holder=prefix+'-volume';app=prefix+'-app'
def docker(*args,check=True):
 r=subprocess.run(['docker',*args],capture_output=True,text=True)
 if check and r.returncode: raise RuntimeError('Docker fixture operation failed: '+args[0])
 return (r.stdout+r.stderr).strip() if args[0]=='logs' else r.stdout.strip()
def root(command):
 return docker('run','--rm','--platform',a.platform,'--network','none','--read-only','--cap-drop','ALL','--cap-add','CHOWN','--cap-add','DAC_OVERRIDE','--user','0:0','--volumes-from',holder,'--entrypoint','sh',a.image,'-c',command)
def start(mode='default'):
 docker('rm','-f',app,check=False)
 options=[]
 if mode=='restricted-bootstrap': options=['--cap-drop','ALL','--cap-add','CHOWN','--cap-add','DAC_OVERRIDE','--cap-add','SETUID','--cap-add','SETGID']
 if mode=='nonroot': options=['--user','10001:10001','--cap-drop','ALL']
 docker('run','-d','--name',app,'--platform',a.platform,'--network','none','--read-only','--security-opt','no-new-privileges',*options,'--volumes-from',holder,a.image)
def healthy():
 import time
 for _ in range(25):
  r=subprocess.run(['docker','exec',app,'wget','-qO-','http://127.0.0.1:8080/healthz'],capture_output=True,text=True)
  if r.returncode==0:
   uid=docker('exec',app,'sh','-c',"awk '/^Uid:/ {print $2}' /proc/1/status")
   caps=docker('exec',app,'sh','-c',"awk '/^CapEff:/ {print $2}' /proc/1/status")
   permitted=docker('exec',app,'sh','-c',"awk '/^CapPrm:/ {print $2}' /proc/1/status")
   nnp=docker('exec',app,'sh','-c',"awk '/^NoNewPrivs:/ {print $2}' /proc/1/status")
   assert uid=='10001' and int(caps,16)==0 and int(permitted,16)==0 and nnp=='1','Mail process privileges changed'
   return
  time.sleep(.2)
 raise RuntimeError('Mail fixture did not become healthy')
def failed_with(text):
 import time
 for _ in range(25):
  if docker('inspect','--format','{{.State.Running}}',app)=='false':break
  time.sleep(.1)
 assert docker('inspect','--format','{{.State.Running}}',app)=='false','Expected safe startup refusal'
 assert text in docker('logs',app),'Expected actionable storage error'
try:
 # Anonymous, empty, nocopy volume starts with Docker's ordinary root:root755.
 docker('create','--name',holder,'--platform',a.platform,'--mount','type=volume,destination=/data,volume-nocopy','--entrypoint','sh',a.image,'-c','true')
 start();healthy()
 original=root('sha256sum /data/master.key')
 assert root('stat -c %a /data')=='755','Directory mode changed'
 docker('stop','-t','1',app)
 root('chown 0:0 /data /data/master.key /data/mail-harbor.db; chmod 600 /data/master.key /data/mail-harbor.db')
 start();healthy();docker('stop','-t','1',app)
 assert root('sha256sum /data/master.key')==original,'Existing key was replaced'
 root('mv /data/master.key /data/master.saved')
 start();failed_with('no replacement key was generated')
 assert root('test ! -e /data/master.key && echo retained')=='retained','Missing key regenerated'
 root('mv /data/master.saved /data/master.key')
 start('restricted-bootstrap');healthy();docker('stop','-t','1',app)
 start('nonroot');healthy()
 print(json.dumps({'ok':True,'platform':a.platform,'freshRootOwnedFolder':True,'rootOwnedExistingFiles':True,'keyPreserved':True,'missingKeyFailsSafely':True,'mailUID':10001,'mailCapabilities':0,'noNewPrivileges':True,'separateInitService':False}))
finally:
 docker('rm','-f',app,check=False)
 # Only this script's newly created anonymous test volume is removed.
 docker('rm','-fv',holder,check=False)
