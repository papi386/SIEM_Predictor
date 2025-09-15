  // tiny helper to generate sparkline + bars
  (function(){
    // sparkline data
    const pts = Array.from({length:28}, ()=> Math.round(Math.random()*480+20));
    const svg = document.getElementById('sparkline');
    const w = 200, h = 72;
    const step = w/(pts.length-1);
    let d = '';
    pts.forEach((v,i)=>{
      const x = (i*step).toFixed(2);
      const y = (h - (v/700*h)).toFixed(2); // scale
      d += (i? ' L ' : 'M ') + x + ' ' + y;
    });
    svg.setAttribute('points', ''); // polyline not used here
    // set polyline path via points attribute
    svg.setAttribute('viewBox','0 0 '+w+' '+h);
    // create polyline element
    const poly = document.querySelector('#sparkline');
    poly.setAttribute('points', pts.map((v,i)=> {
      const x = (i*step);
      const y = (h - (v/700*h));
      return x + ',' + y;
    }).join(' '));

    // set peak value text
    const peak = Math.max(...pts);
    document.getElementById('peakVal').textContent = peak;

    // bars
    const barContainer = document.getElementById('barContainer');
    for(let i=0;i<12;i++){
      const val = Math.round(Math.random()*100+20);
      const div = document.createElement('div');
      div.style.height = (20 + val) + "px";
      div.title = val;
      barContainer.appendChild(div);
    }

    // eventRate update small animation
    const ev = document.getElementById('eventRate');
    let cur = parseInt(ev.textContent,10) || 135;
    setInterval(()=> {
      cur = Math.max(10, cur + Math.floor(Math.random()*21-10));
      ev.textContent = cur;
    }, 2500);

  })();



