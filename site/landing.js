(function(){
  var d=document, root=d.documentElement;
  var reduce=window.matchMedia&&matchMedia('(prefers-reduced-motion: reduce)').matches;

  function tablist(tabs,keysNext,keysPrev,onSel){
    function sel(t,focus){
      tabs.forEach(function(x){var on=x===t;x.setAttribute('aria-selected',on);x.tabIndex=on?0:-1;d.getElementById(x.getAttribute('aria-controls')).hidden=!on;});
      if(onSel)onSel(t);
      if(focus)t.focus();
    }
    tabs.forEach(function(t,i){
      t.addEventListener('click',function(){sel(t)});
      t.addEventListener('keydown',function(e){
        var k=e.key,n=null;
        if(k===keysNext)n=tabs[(i+1)%tabs.length];else if(k===keysPrev)n=tabs[(i-1+tabs.length)%tabs.length];else if(k==='Home')n=tabs[0];else if(k==='End')n=tabs[tabs.length-1];
        if(n){e.preventDefault();sel(n,true);}
      });
    });
  }

  d.querySelectorAll('[data-tabs]').forEach(function(box){
    tablist([].slice.call(box.querySelectorAll('[role="tab"]')),'ArrowRight','ArrowLeft');
    var cp=box.querySelector('[data-copy]');
    if(cp)cp.addEventListener('click',function(){
      var p=box.querySelector('[role="tabpanel"]:not([hidden]) pre');
      var txt=p?p.innerText:'';
      if(navigator.clipboard&&navigator.clipboard.writeText){
        navigator.clipboard.writeText(txt).then(function(){cp.textContent='copied';setTimeout(function(){cp.textContent='copy'},2000)},function(){cp.textContent='select and copy'});
      }else{cp.textContent='select and copy';}
    });
  });

  var featMeta=d.querySelector('[data-feat-meta]');
  var files={'b-exec':'loop.py','b-repo':'repo.py','b-bg':'server.py','b-reset':'grader.py','b-pty':'shell'};
  d.querySelectorAll('[data-feat]').forEach(function(list){
    tablist([].slice.call(list.querySelectorAll('[role="tab"]')),'ArrowDown','ArrowUp',function(b){if(featMeta)featMeta.textContent=files[b.id]||''});
  });

  /* signature: hosted beta / self-hosted */
  var sw=d.querySelector('[data-switch]');
  if(sw){
    var line=d.querySelector('[data-baseurl]'), zone=d.querySelector('[data-zone]'), net=d.querySelector('[data-net]'), wire=d.querySelector('[data-wire]');
    var lbl=d.querySelector('[data-zone-label]'), sub=d.querySelector('[data-zone-sub]');
    var cap=d.querySelector('[data-topo-cap]'), wmeta=d.querySelector('[data-ways-meta]');
    var M={
      ours:{url:'https://&lt;beta endpoint&gt;',key:'KEY',x:236,w:200,wire:'M108 150 H252 V166',lbl:'hosted beta',sub:'shared evaluation VM',meta:'evaluation',cap:'Hosted beta: the API and the sandboxes run on our evaluation instance, outside your network.'},
      yours:{url:'https://sandfort.acme.internal',key:'KEY',x:0,w:444,wire:'M108 150 V166',lbl:'your hosts',sub:'your Docker host or node',meta:'production',cap:'Self-hosted: the API, the sandboxes and the audit chain sit inside your network.'}
    };
    function setMode(m,user){
      var c=M[m];
      sw.dataset.mode=m;
      sw.querySelectorAll('[data-mode-btn]').forEach(function(b){b.setAttribute('aria-pressed',b.dataset.modeBtn===m)});
      line.innerHTML='client = Client(base_url=<span class="s">"'+c.url+'"</span>, api_key='+c.key+')';
      if(user){line.classList.add('flash');setTimeout(function(){line.classList.remove('flash')},600);}
      zone.style.transform='translateX('+c.x+'px)';
      net.setAttribute('width',c.w);
      wire.setAttribute('d',c.wire);
      lbl.textContent=c.lbl; sub.textContent=c.sub; cap.textContent=c.cap; wmeta.textContent=c.meta;
      var tz=d.querySelector('[data-tm-zone]');
      if(tz){var tin=d.querySelector('[data-tm-in]'),tout=d.querySelector('[data-tm-out]');(m==='yours'?tin:tout).appendChild(tz);tin.classList.toggle('has',m==='yours');tout.classList.toggle('has',m!=='yours');d.querySelector('[data-tm-lbl]').textContent=m==='yours'?'your hosts \u00b7 your Docker host or node':'hosted beta \u00b7 shared evaluation VM';}
      d.querySelectorAll('.compare [data-col]').forEach(function(td){td.classList.toggle('on',td.dataset.col===m)});
    }
    sw.querySelectorAll('[data-mode-btn]').forEach(function(b){b.addEventListener('click',function(){setMode(b.dataset.modeBtn,true)})});
    setMode('ours',false);
  }

  /* reveal */
  if('IntersectionObserver' in window && !reduce){
    root.classList.add('js');
    var io=new IntersectionObserver(function(es){es.forEach(function(e){if(e.isIntersecting){e.target.classList.add('in');io.unobserve(e.target);}})},{rootMargin:'0px 0px -6% 0px',threshold:.06});
    d.querySelectorAll('.rv').forEach(function(el){io.observe(el)});
  }

  /* hero REPL: type each input line, print its output, hold the final frame */
  var pre=d.getElementById('repl'), replay=d.querySelector('[data-replay]');
  if(pre){
    var full=pre.innerHTML, lines=full.split('\n'), timer=null;
    function plain(h){var t=d.createElement('div');t.innerHTML=h;return t.textContent;}
    function play(){
      clearTimeout(timer); if(replay)replay.hidden=true;
      pre.parentNode.style.setProperty('--repl-h',pre.offsetHeight+'px');
      var i=0, shown=[];
      function nextLine(){
        if(i>=lines.length){pre.innerHTML=full;if(replay)replay.hidden=false;return;}
        var l=lines[i++], isInput=l.indexOf('&gt;&gt;&gt;')>-1;
        if(!isInput){shown.push(l);pre.innerHTML=shown.join('\n')+'\n<span class="cursor"></span>';timer=setTimeout(nextLine,520);return;}
        var prompt='<span class="p">&gt;&gt;&gt; </span>', body=l.replace(/^<span class="p">&gt;&gt;&gt; <\/span>/,''), txt=plain(body), n=0;
        (function typeCh(){
          n=Math.min(txt.length,n+2);
          var partial=n<txt.length?prompt+txt.slice(0,n).replace(/&/g,'&amp;').replace(/</g,'&lt;'):l;
          pre.innerHTML=shown.concat([partial]).join('\n')+'<span class="cursor"></span>';
          if(n<txt.length){timer=setTimeout(typeCh,26);}else{shown.push(l);timer=setTimeout(nextLine,260);}
        })();
      }
      pre.innerHTML='<span class="cursor"></span>';
      timer=setTimeout(nextLine,500);
    }
    if(!reduce){play(); if(replay)replay.addEventListener('click',play);}
  }
})();
