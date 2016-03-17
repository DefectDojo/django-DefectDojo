/* * The MIT License

Copyright (c) 2012, 2013 by Juergen Marsch

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
    var pluginName = "radar", pluginVersion = "0.1";
    var options ={ 
        series:{ 
            radar:{ 
                active: false,
                show: false,
                radarSize: 0.8,
                delay:10,
                angleStep:1,
                angleSize:10,
                angleSteps:6,
                color: "darkgreen",
                backColor: "darkgreen"
            }
        }
    };
    var replaceOptions = { grid:{ show:false } };
    function init(plot){ 
        var maxRadius = null, centerLeft = null, centerTop = null;
        var opt = null, series = null, data = null;
        var rcanvas = null, rctx = null,rfunc = null, rangle = 0;
        plot.hooks.processOptions.push(processOptions);
        function processOptions(plot,options){ 
            if(options.series.radar.active===true){
                $.extend(true,options,replaceOptions);
                opt = options;
                plot.hooks.processRawData.push(processRawData);
                plot.hooks.draw.push(draw);
            }
        }  
        function processRawData(plot,s,data,datapoints){
            if(s.radar.show === true)
            { }
        }
        function draw(plot, ctx){
            data = plot.getData();
            opt = plot.getOptions();
            clear(ctx);
            setupRadar(ctx);
            for(var i = 0; i < data.length; i++){ drawSerie(plot,ctx,data[i]); }
            rfunc = window.setInterval(rotating, opt.series.radar.delay);
        }
        function rotating(){
            var angleSize = opt.series.radar.angleSize,
                angleSteps = opt.series.radar.angleSteps,
                alpha,
                rangleStart;
            clear(rctx);
            rctx.lineWidth = 1;
            for(var i = 1; i <= angleSteps;i++){
                alpha = (angleSteps - i + 1) / 10;
                rangleStart = (i - 1) * angleSize + rangle;
                drawRotatePart("rgba(255,255,255," + alpha + ")",rangleStart, angleSize + rangleStart);
            }
            drawRotatePart(opt.series.radar.backColor,rangle + angleSteps * angleSize,rangle);
            rangle = rangle + opt.series.radar.angleStep;
            if(rangle>359) { rangle = 0; }
        }
        function drawRotatePart(c,angles,anglet){
            var s = 2 * Math.PI * angles / 360,
                t = 2 * Math.PI * anglet / 360,          
                x = centerLeft + Math.round(Math.cos(s) * maxRadius),
                y = centerTop + Math.round(Math.sin(s) * maxRadius);
            rctx.strokeStyle = c;
            rctx.fillStyle = c;
            rctx.beginPath();
            rctx.moveTo(centerLeft,centerTop);
            rctx.lineTo(x,y);
            rctx.arc(centerLeft,centerTop,maxRadius,s,t);
            rctx.lineTo(centerLeft,centerTop);
            rctx.closePath();
            rctx.fill();  
        }
        function clear(ctx){
            ctx.clearRect(0,0,ctx.canvas.width,ctx.canvas.height);
        }
        function setupRadar(ctx){
            maxRadius =  Math.min(ctx.canvas.width,ctx.canvas.height)/2 * opt.series.radar.radarSize;
            centerTop = (ctx.canvas.height/2);
            centerLeft = centerTop;
            ctx.beginPath();
            ctx.lineWidth = 2;
            ctx.strokeStyle = opt.series.radar.color;
            ctx.fillStyle = opt.series.radar.backColor;
            ctx.arc(centerTop,centerLeft,maxRadius,0,Math.PI * 2,true);
            ctx.closePath();
            ctx.fill();
            rcanvas = document.createElement('canvas');
            rcanvas.width = ctx.canvas.width;
            rcanvas.height = ctx.canvas.height;
            $(rcanvas).css({ position: 'absolute', left: 0, top: 0 });
            $(rcanvas).appendTo(plot.getPlaceholder());
            rctx = rcanvas.getContext("2d");
        }
        function drawSerie(plot,ctx,serie) {
            if(opt.series.radar.debug.active === true) { series = serie;}
            for(var i = 0; i < serie.data.length; i++){ drawItem(plot,ctx,serie,serie.data[i]);}
        }
        function drawItem(plot,ctx,serie,item){
            var s = 2 * Math.PI * item[0] / 360,
                itemSize = serie.radar.itemSize,
                x = centerLeft + Math.round(Math.cos(s) * maxRadius * item[1] / 100) - itemSize,
                y = centerTop + Math.round(Math.sin(s) * maxRadius * item[1] / 100) - itemSize;
            ctx.beginPath();
            ctx.lineWidth = 1;
            ctx.fillStyle = serie.color;
            ctx.strokeStyle = serie.color;
            ctx.arc(x,y,itemSize,0,Math.PI * 2,true);
            ctx.closePath();
            ctx.fill();
        }
    }
    $.plot.plugins.push({
        init: init,
        options: options,
        name: pluginName,
        version: pluginVersion
    });
})(jQuery);	
