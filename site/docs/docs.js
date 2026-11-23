
(function(){
  var d=document;
  var status=d.getElementById('copy-status');
  function say(msg){
    if(!status)return;
    status.textContent='';
    setTimeout(function(){status.textContent=msg},50);
    setTimeout(function(){status.textContent=''},2500);
  }
  d.querySelectorAll('[data-copy]').forEach(function(b){
    b.addEventListener('click',function(){
      var slab=b.closest('.slab');var pre=slab&&slab.querySelector('pre');
      var txt=pre?pre.innerText:'';
      function done(){
        say('Copied');b.textContent='Copied';
        setTimeout(function(){b.textContent='Copy'},1600)
      }
      function fail(){say('Copy failed')}
      var cb=navigator.clipboard;
      if(cb&&cb.writeText){cb.writeText(txt).then(done,fail)}else{fail()}
    });
  });
  var toc=d.querySelector('details.toc');
  if(toc&&window.matchMedia&&matchMedia('(min-width:1024px)').matches){toc.open=true}
})();
