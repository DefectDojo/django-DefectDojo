/*
 * The MIT License

Copyright (c) 2010, 2011, 2012, 2013 by Juergen Marsch

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

(function ($) {
    "use strict";
    var pluginName = "spiral", pluginVersion = "0.3";
    var options = {
        series: { 
            spiral: {
                active: false,
                show: false,
                spiralSize: 0.8,
                rotations: 3,
                steps : 36,
                delay: 50,
                highlight: { opacity: 0.5 }
            }
        }
    };
    var defaultOptions = {
        series:{
            nearBy:{
                distance: 6,
                findItem: null,
                findMode: "circle",
                drawEdit: null,
                drawHover: null
            }
        }
    };
    var replaceOptions = { grid:{show:false} };
    function init(plot) {
        var offset = null,opt = null,series = null,lctx;
        var colors,sumPies,maxRadius,centerLeft,centerTop;
        var stepNo,rotationNo,pies = [],rfunc,angleStart;
        plot.hooks.processOptions.push(processOptions);
        function processOptions(plot,options){
            if(options.series.spiral.active===true){
                $.extend(true,options,replaceOptions);
                $.plot.JUMlib.data.extendEmpty(options,defaultOptions);
                opt = options;
                plot.hooks.drawSeries.push(drawSeries);
            }
        }
        function drawSeries(plot, ctx, serie){
            var j;
            if (serie.spiral.show) {
                series = serie;
                offset = plot.getPlotOffset();
                colors = createColors(opt,serie.data.length);
                maxRadius =  Math.min(ctx.canvas.width,ctx.canvas.height)/2 * opt.series.spiral.spiralSize;
                centerTop = (ctx.canvas.height/2);
                centerLeft = centerTop;
                lctx = ctx;
                sumPies = 0;
                for(j = 0; j < serie.data.length; j++){ sumPies += serie.data[j].data;}
                for(j = 0; j < serie.data.length; j++) {
                    pies.push({data: serie.data[j].data, size: serie.data[j].data / sumPies * 360});
                }
            }
            stepNo = 1;
            rotationNo = 1;
            rfunc = window.setInterval(spiraling, opt.series.spiral.delay);
        }
        function spiraling(){
            var radius,angle,l_stepNo,l_steps,color;
            lctx.clearRect(0,0,lctx.canvas.width,lctx.canvas.height);
            if(opt.series.spiral.rotations === 0){
                angleStart = 0;
                l_steps = opt.series.spiral.steps;
            }
            else{
                angleStart = stepNo * 360 / opt.series.spiral.steps;
                l_steps = opt.series.spiral.steps * opt.series.spiral.rotations;
            }
            for(var i = 0; i < pies.length; i++){
                l_stepNo = (rotationNo - 1) * opt.series.spiral.steps + stepNo;
                radius = l_stepNo / l_steps * maxRadius;
                angle = l_stepNo / l_steps * pies[i].size;
                color = getColor(
                    {ctx:lctx,serie:series,dataIndex:i,colors:colors,
                    radius:radius,left:centerLeft,top:centerTop});
                drawPie(lctx,angleStart,angleStart + angle,radius,color);
                angleStart += angle; 
            }
            stepNo++;
            if(stepNo > opt.series.spiral.steps){
                stepNo = 1;
                rotationNo++;
                if(rotationNo > opt.series.spiral.rotations) {
                    window.clearInterval(rfunc);
                    series.nearBy.findItem = findNearbyItemSpiral;
                    series.nearBy.drawHover = drawHoverSpiral;
                }
            }
        }
        function drawPie(lctx,anglestart,angleEnd,radius,color){
            var s = 2 * Math.PI * angleStart / 360,
                t = 2 * Math.PI * angleEnd / 360,          
                x = centerLeft + Math.round(Math.cos(s) * radius),
                y = centerTop + Math.round(Math.sin(s) * radius);
            lctx.strokeStyle = color;
            lctx.fillStyle = color;
            lctx.beginPath();
            lctx.moveTo(centerLeft,centerTop);
            lctx.lineTo(x,y);
            lctx.arc(centerLeft,centerTop,radius,s,t);
            lctx.lineTo(centerLeft,centerTop);
            lctx.closePath();
            lctx.fill();      
        }
        function findNearbyItemSpiral(mouseX,mouseY,i,serie){
            return findNearby(mouseX,mouseY,i,serie);
            function findNearby(mouseX,mouseY,i,serie){
                var item = null,j;
                angleStart = 0;
                for(j = 0; j < pies.length; j++){
                    lctx.save();
                    lctx.beginPath();
                    var s = 2 * Math.PI * angleStart / 360,
                        t = 2 * Math.PI * (angleStart + pies[j].size) / 360,          
                        x = centerLeft + Math.round(Math.cos(s) * maxRadius),
                        y = centerTop + Math.round(Math.sin(s) * maxRadius);
                    lctx.moveTo(centerLeft,centerTop);
                    lctx.lineTo(x,y);
                    lctx.arc(centerLeft,centerTop,maxRadius,s,t);
                    lctx.closePath();
                    if (lctx.isPointInPath(mouseX, mouseY)){ 
                        item = [i,j]; 
                        lctx.restore(); 
                        return item;
                    } 
                    angleStart += pies[j].size;            
                }
                return item;	        
            }
        }
        function drawHoverSpiral(octx,serie,dataIndex){
            angleStart = 0;
            for (var i = 0; i < dataIndex; i++){ angleStart += pies[i].size;}
            var c = "rgba(255,255,255," + serie.spiral.highlight.opacity + ")";
            drawPie(octx,angleStart,angleStart + pies[dataIndex].size,maxRadius,c);
        }
    }
    var between = $.plot.JUMlib.library.between;
    var createFont = $.plot.JUMlib.data.createFont;
    var createColors = $.plot.JUMlib.data.createColors;
    var getColor = $.plot.JUMlib.data.getColor;
    $.plot.plugins.push({
        init: init,
        options: options,
        name: pluginName,
        version: pluginVersion
    });
})(jQuery);