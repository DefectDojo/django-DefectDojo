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
    var pluginName = "bubbles", pluginVersion = "0.3";
    var options = {
        series: { 
            bubbles: {
                active: false,
                show: false,
                fill: true,
                lineWidth: 2,
                highlight: { opacity: 0.5 },
                drawbubble: drawbubbleDefault,
                bubblelabel: { show:false, fillStyle:"black"}
            }
        }
    };
    var defaultOptions = {
        series:{
            editMode: 'xy',    //could be none, x, y, xy, v
            nearBy:{
                distance: 6,
                findMode: "circle"
            }
        }
    };
    function drawbubbleDefault(ctx,serie,x,y,v,r,c,overlay){
        ctx.fillStyle = c;
        ctx.strokeStyle = c;
        ctx.lineWidth = serie.bubbles.lineWidth;
        ctx.beginPath();
        ctx.arc(x,y,r,0,Math.PI*2,true);
        ctx.closePath();
        if (serie.bubbles.fill) { ctx.fill();} else { ctx.stroke(); }
        if(serie.bubbles.bubblelabel.show) {drawbubbleLabel(ctx,serie,x,y,v); }
        // based on a patch from Nikola Milikic
        function drawbubbleLabel(ctx,serie,x,y,v){	
            var xtext,ytext,vsize,f;
            ctx.fillStyle = serie.bubbles.bubblelabel.fillStyle;
            f = serie.xaxis.font;
            //ctx.font = f.style + " " + f.variant + " " + f.weight + " " + f.size + "px '" + f.family + "'";
            vsize = ctx.measureText(v); 
            xtext = x - vsize.width/2;
            //ytext = y + f.size/2;
            ytext = y + 4;
            ctx.fillText(v,xtext,ytext);
        }
    }
    function init(plot) {
        var offset = null,opt = null,series = null;
        plot.hooks.processOptions.push(processOptions);
        function processOptions(plot,options){
            if(options.series.bubbles.active){
                $.plot.JUMlib.data.extendEmpty(options,defaultOptions);                
                opt = options;
                plot.hooks.processRawData.push(processRawData);
                plot.hooks.drawSeries.push(drawSeries);
            }
        }
        function processRawData(plot,s,data,datapoints){
            if(s.bubbles.show == true){
                //s.nearBy.drawHover = drawHoverBubbles; 
                //s.nearBy.findItem = findNearbyItemBubbles;
            }
        }
        function drawSeries(plot, ctx, serie){
            if (serie.bubbles.show) {
                if(opt.series.bubbles.debug.active === true) { series = serie;}
                offset = plot.getPlotOffset();
                for (var j = 0; j < serie.data.length; j++) { drawbubble(ctx,serie, serie.data[j], serie.color);}
            }
        }
        function drawbubble(ctx,serie,data,c,overlay){
            var x,y,r,v;
            x = offset.left + serie.xaxis.p2c(data[0]);
            y = offset.top + serie.yaxis.p2c(data[1]);
            v = data[2];
            r = parseInt(serie.yaxis.scale * data[2] / 2,0);
            serie.bubbles.drawbubble(ctx,serie,x,y,v,r,c,overlay);
        }
        function findNearbyItemBubbles(mouseX, mouseY,i,serie){
            var item = null;
            if(opt.series.justEditing){
                if(opt.series.justEditing[1].seriesIndex === i){ item = findNearbyItemEdit(mouseX,mouseY,i,serie);}
            }
            else{ 
                if(opt.grid.editable){ item = findNearbyItemForEdit(mouseX,mouseY,i,serie);}
                else{ item = findNearbyItem(mouseX,mouseY,i,serie);}        
            }
            return item;
            function findNearbyItemEdit(mouseX,mouseY,i,serie){}
        }
        function findNearbyItemBubblesOld(mouseX, mouseY,i,serie){
            var item = null;
            if(!serie.justEditing){ item = findNearbyItem(mouseX,mouseY,i,serie); }
            return item;
        }
        function findNearbyItemOld(mouseX, mouseY,i,serie){
            var item = null;		
            if (serie.bubbles.show) {
                for (var j = 0; j < serie.data.length; j++) {
                    var dataitem = serie.data[j];
                    var dx = Math.abs(axes.xaxis.p2c(dataitem[0]) - mouseX),
                        dy = Math.abs(axes.yaxis.p2c(dataitem[1]) - mouseY),
                        dist = Math.sqrt(dx * dx + dy * dy);
                    if (dist <= dataitem[2]) { item = [i,j];}
                }
                return item;
            }
        }
        function drawHoverBubbles(octx,serie,point,dataIndex,edit){
            octx.save();
            octx.translate(-offset.left,-offset.top);
            var c = "rgba(255, 255, 255, " + serie.bubbles.highlight.opacity + ")";
            drawbubble(octx, serie, serie.data[dataIndex], c, true);
            octx.restore();
        }
    }
    $.plot.plugins.push({
        init: init,
        options: options,
        name: pluginName,
        version: pluginVersion
    });
})(jQuery);