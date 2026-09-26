(function(){
  const sidebar=document.querySelector('.sidebar');
  const topbar=document.querySelector('.topbar');
  if(!sidebar||!topbar) return;
  const b=document.createElement('button'); b.className='sidebar-toggle'; b.title='Collapse navigation'; b.setAttribute('aria-label','Collapse navigation'); b.textContent='☰';
  topbar.prepend(b);
  const collapsed=localStorage.getItem('aegisSidebarCollapsed')==='1';
  if(collapsed) sidebar.classList.add('collapsed');
  b.addEventListener('click',()=>{
    sidebar.classList.toggle('collapsed');
    localStorage.setItem('aegisSidebarCollapsed',sidebar.classList.contains('collapsed')?'1':'0');
  });
})();
