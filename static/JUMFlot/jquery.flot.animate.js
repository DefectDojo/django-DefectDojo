/* * The MIT License

Copyright (c) 2013 by Juergen Marsch

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
(function ($){
    "use strict";
    var pluginName = "animate", pluginVersion = "0.2";
    var options ={
        animate:{
            active:false,
            mode:"tile",  //tile,pixastic, more to follow
            tile:{ x:3, y:3, mode:"lt"},   //
            pixastic:{ maxValue: 1, mode:"blurfast"},
            sorting: {x:5,y:5, mode:"bubble"},
            stepDelay:500,
            steps:20
        }
    };
    function init(plot,classes){
        var opt,offset,animateFunc,lctx;;
        plot.hooks.processOptions.push(processOptions);
        function processOptions(plot,options){
            if(options.animate.active === true){
                plot.hooks.draw.push(draw);
                plot.hooks.bindEvents.push(bindEvents);
                opt = options;
            }
        }
        function draw(plot,ctx){
            lctx = ctx;
            opt = plot.getOptions();
            offset = plot.getPlotOffset();
        }
        function bindEvents(plot,eventHolder){
            var acanvas,actx;
            acanvas = document.createElement('canvas');
            actx = acanvas.getContext("2d");
            actx.canvas.width = lctx.canvas.width;
            actx.canvas.height = lctx.canvas.height;
            actx.putImageData(lctx.getImageData(0,0,lctx.canvas.width,lctx.canvas.height),0,0);
            lctx.clearRect(0,0,lctx.canvas.width,lctx.canvas.height);
            switch(opt.animate.mode){
                case "tile":
                    animateTile(opt.animate.tile); break;
                case "pixastic":
                    animatePixastic(opt.animate.pixastic); break;
                case "sorting":
                    animateSorting(opt.animate.sorting); break;
                default:
                    lctx.putImageData(actx.getImageData(0,0,actx.canvas.width,actx.canvas.height),0,0);
            }
            function animatePixastic(){
                var duration, stepValue, stepRange, params = {}, paramName, startdate = new Date();
                switch(opt.animate.pixastic.mode){
                    case "blurfast":
                        stepValue = Math.abs(opt.animate.pixastic.maxValue) * 2.5;
                        paramName = "amount"; params = { amount: 2.5}; break;
                    case "lighten":
                        stepValue = Math.min(1,Math.max(-1,opt.animate.pixastic.maxValue));
                        paramName = "amount"; params = { amount: 1}; break;
                    case "emboss":
                        stepValue = Math.abs(opt.animate.pixastic.maxValue) * 10; 
                        paramName = "strength"; params = { greyLevel:127, direction: "topleft", blend: true}; break;
                    case "mosaic":
                        stepValue = parseInt(Math.abs(opt.animate.pixastic.maxValue) * 100);
                        paramName = "blockSize"; params = { blockSize:100}; break;
                    case "noise":
                        stepValue = Math.abs(opt.animate.pixastic.maxValue);
                        paramName = "strength"; params = {mono:true,amount:1.0,strength:0.5}; break;
                    default:
                        stepValue = Math.min(1,Math.max(-1,opt.animate.pixastic.maxValue));
                }
                stepRange = stepValue / opt.animate.steps;
                animating();
                duration = opt.animate.stepDelay - (new Date() - startdate);
                animateFunc = window.setInterval(animating, duration);
                function animating(){
                    var r;
                    params[paramName] = stepValue; 
                    if(stepValue === 0){
                        lctx.putImageData(actx.getImageData(0,0,actx.canvas.width,actx.canvas.height),0,0);
                        window.clearInterval(animateFunc);
                    }
                    else{
                        r = Pixastic.process(actx.canvas,opt.animate.pixastic.mode, params).getContext("2d");
                        lctx.putImageData(r.getImageData(0,0,r.canvas.width,r.canvas.height),0,0);
                        stepValue -= stepRange;
                        if((stepRange > 0 && stepValue <= 0) || (stepRange < 0 && stepValue >= 0)) { stepValue = 0;}
                    }                   
                }               
            }
            function animateTile(lopt){
                var x,y,flds = [],w = lctx.canvas.width / lopt.x,h = lctx.canvas.height / lopt.y,
                    startdate = new Date(),duration = opt.animate.stepDelay;
                switch(lopt.mode){
                    case "lt": x = 0; y = 0; break;
                    case "tl": x = 0; y = 0; break;
                    case "rb": x = lopt.x - 1; y = lopt.y - 1; break;
                    case "br": x = lopt.x - 1; y = lopt.y - 1; break;
                    case "random":
                        for(var i = 0; i < lopt.x; i++){ for(var j = 0; j < lopt.y; j++){flds.push([i,j]);} }
                        var r = parseInt(Math.random() * flds.length);
                        x = flds[r][0]; y = flds[r][1]; flds.splice(r,1);
                        break;
                }
                animating();
                duration = duration - (new Date() - startdate);
                animateFunc = window.setInterval(animating, duration);                
                function animating(){
                    lctx.putImageData(actx.getImageData(x * w,y * h,w,h),x * w, y * h);
                    nextStep();
                }
                function nextStep(){
                    switch(lopt.mode){
                        case "lt":
                            if(x++ >= lopt.x) { x = 0; if(y++ >= lopt.y){window.clearInterval(animateFunc);} }
                            break;
                        case "tl":
                            if(y++ >= lopt.y) { y = 0; if (x++ >= lopt.x){window.clearInterval(animateFunc);} }
                            break;
                        case "rb":
                            if(x-- < 0) { x = lopt.x - 1; if(y-- < 0) {window.clearInterval(animateFunc);} }
                            break;
                        case "br":
                            if(y-- < 0) { y = lopt.y - 1; if(x-- < 0) {window.clearInterval(animateFunc);} }
                            break;
                        case "random":
                            if(flds.length === 0){window.clearInterval(animateFunc);}
                            else{
                                var r = parseInt(Math.random() * flds.length);
                                x = flds[r][0]; y = flds[r][1]; flds.splice(r,1);
                            }
                            break;
                    }
                }
            }
            function animateSorting(lopt){
                var lfd = [], unsorted = [],changing = [], l = lopt.x * lopt.y,t,
                    w = lctx.canvas.width / lopt.x,h = lctx.canvas.height / lopt.y,
                    duration = opt.animate.stepDelay, startdate = new Date();
                for(var i = 0; i < l; i++){ lfd.push(i); }
                for(var i = l - 1; i >=0; i--){ t = Math.floor(Math.random() * i); unsorted.push(lfd[t]); lfd.splice(t,1);}
                drawUnsorted(unsorted);
                switch(lopt.mode){
                    case "bubble":
                        changing = bubbleSort(unsorted); break;
                    case "quick":
                        changing = quickSort(unsorted); break;
                    case "selection":
                        changing = selectionSort(unsorted); break;
                    default:
                        changing = bubbleSort(unsorted);
                }
                animating();
                duration = duration - (new Date() - startdate);
                animateFunc = window.setInterval(animating,duration);
                function drawUnsorted(a){
                    var x,y,x2,y2;
                    for(var i = 0; i < a.length; i++){ 
                        y = Math.floor(a[i] / lopt.x);
                        x = a[i] - y * lopt.x;
                        y2 = Math.floor(i / lopt.x);
                        x2 = i - y2 * lopt.y;
                        lctx.putImageData(actx.getImageData(x * w,y * h,w,h),x2 * w, y2 * h);
                    }
                }
                function bubbleSort(a){
                    var n=0, z=0, change = [], h;
                    while (n < a.length) {
                        z=0;
                        while (z < a.length - n - 1) {
                            if (a[z] > a[z+1]) { 
                                h = a[z]; a[z] = a[z+1]; a[z+1] = h;
                                change.push([z,z+1]); 
                            }
                            ++z;
                        }
                        ++n;
                    }
                    return change;
                }
                function quickSort(a){
                    var chng = [];
                    quickSortSub(a,0,a.length-1);
                    return chng;
                    function quickSortSub(a, l, r) {
                        var index;
                        if (a.length > 1) {
                            index = partition(a, l, r);
                            if (l < index - 1) {quickSortSub(a, l, index - 1); }
                            if (index < r) {quickSortSub(a, index, r); }
                        }
                        return a;
                    }
                    function partition(a, l, r) {
                        var pivot = a[Math.floor((r + l) / 2)],i = l,j = r, z;
                        while (i <= j) {
                            while (a[i] < pivot) { i++; }
                            while (a[j] > pivot) { j--; }
                            if (i <= j) {
                                z = a[i]; a[i] = a[j]; a[j] = z;
                                chng.push([i,j]); i++; j--;
                            }
                        }
                        return i;
                    }
                }
                function selectionSort(a){
                    var len = a.length,min, t,j, chng = [];
                    for (i=0; i < len; i++){
                        min = i;
                        for (j=i+1; j < len; j++){ if (a[j] < a[min]){ min = j; } }
                        if (i != min){ t = a[i]; a[i] = a[min];a[min] = t; chng.push([i,min]); }
                    }
                    return chng;
                }
                function animating(){
                    var tmp1,tmp2,x,y,x2,y2;
                    if(changing.length === 0){ window.clearInterval(animateFunc);}
                    else{
                        y = Math.floor(changing[0][0] / lopt.x);
                        x = changing[0][0] - y * lopt.x;
                        y2 = Math.floor(changing[0][1] / lopt.x);
                        x2 = changing[0][1] - y2 * lopt.x;
                        changing.splice(0,1);
                        tmp1 = lctx.getImageData(x * w, y * h,w,h);
                        tmp2 = lctx.getImageData(x2 * w, y2 * h,w,h);
                        lctx.putImageData(tmp2,x * w, y * h);
                        lctx.putImageData(tmp1,x2 * w, y2 * h); 
                    }
                }
            }
        }
    }
    var getColor = $.plot.JUMlib.data.getColor;
    $.plot.plugins.push({
        init: init,
        options: options,
        name: pluginName,
        version: pluginVersion
    });
})(jQuery);