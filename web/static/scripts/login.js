async function doLogin(){
  const btn=document.getElementById('login-btn');
  const err=document.getElementById('error-msg');
  const user=document.getElementById('username').value.trim();
  const pass=document.getElementById('password').value;
  if(!user||!pass){err.textContent='Please fill in all fields';err.style.display='block';return;}
  btn.disabled=true;btn.textContent='Signing in...';err.style.display='none';
  try{
    const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:user,password:pass})});
    const data=await r.json();
    if(!r.ok||data.error){err.textContent=data.detail||data.error||'Login failed';err.style.display='block';btn.disabled=false;btn.textContent='Sign In';return;}
    localStorage.setItem('pentestai_token',data.token||data.access_token);
    localStorage.setItem('pentestai_user',JSON.stringify({user_id:data.user_id,username:data.username||user,role:data.role||'pentester',skill_level:data.skill_level||'intermediate'}));
    document.cookie='pentestai_token='+(data.token||data.access_token)+'; path=/; SameSite=Strict';
    window.location.href='/';
  }catch(e){err.textContent='Connection error';err.style.display='block';btn.disabled=false;btn.textContent='Sign In';}
}
// Auto-redirect if already logged in
if(localStorage.getItem('pentestai_token'))window.location.href='/';
