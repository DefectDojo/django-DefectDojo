/*
 * The MIT License

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

(function ($) {
    "use strict";
    var pluginName = "rectangle", pluginVersion = "0.3";
    var options = {
        series: { 
            rectangle: {
                active: false,
                show: false,
                fill: true,
                lineWidth: 2,
                directions: "tlbr",   //any combination of first char for top,left,bottom,right
                highlight: { opacity: 0.5 },
                drawRectangle: drawRectangleDefault,
                label: { show:false, fillStyle:"black"}
            }
        }
    };
    var replaceOptions = {
        grid:{show:false},
        xaxes:[{min:0,max:100}],
        yaxes:[{min:0,max:100}]
    };
    var defaultOptions = {
        series:{
            editMode: 'none',    //could be none, x, y, xy, v
            nearBy:{
                distance: 6,
                findMode: "circle"
            }
        }
    };
    function drawRectangleDefault(ctx,serie,dataIndex){
        var d = serie.data[dataIndex];
        ctx.save();
        ctx.linewidth = serie.rectangle.lineWidth;
        if(serie.rectangle.fill === true){
            ctx.fillStyle = d.pos.color;
            ctx.fillRect(d.pos.x,d.pos.y,d.pos.w,d.pos.h);
        }
        else{
            ctx.strokeStyle = d.pos.color;
            ctx.strokeRect(d.pos.x,d.pos.y,d.pos.w,d.pos.h);
        }
        ctx.restore();
        ctx.fillStyle = serie.color;
        ctx.strokeStyle = serie.color;
        ctx.lineWidth = serie.rectangle.lineWidth;
        if(serie.rectangle.label.show) {drawRectangleLabel(ctx,serie,d); }
        function drawRectangleLabel(ctx,serie,d){	
            var xtext,ytext,vsize,f;
            ctx.fillStyle = serie.rectangle.label.fillStyle;
            f = serie.xaxis.options.font;
            ctx.font = f.style + " " + f.variant + " " + f.weight + " " + f.size + "px '" + f.family + "'";
            vsize = ctx.measureText(d.label); 
            xtext = d.pos.x + d.pos.w/2 - vsize.width/2;
            ytext = d.pos.y + d.pos.h/2;
            ctx.fillText(d.label,xtext,ytext);
        }
    }
    function init(plot) {
        var offset = null,opt = null,series = null,colors,sumRect;
        plot.hooks.processOptions.push(processOptions);
        function processOptions(plot,options){
            if(options.series.rectangle.active){
                $.extend(true,options,replaceOptions);
                $.plot.JUMlib.data.extendEmpty(options,defaultOptions);
                opt = options;
                plot.hooks.processRawData.push(processRawData);
                plot.hooks.drawSeries.push(drawSeries);
            }
        }
        function processRawData(plot,s,data,datapoints){
            if(s.rectangle.show === true){
                s.nearBy.drawHover = drawHoverRectangle; 
                s.nearBy.findItem = findNearbyItemRectangle;
            }
        }
        function drawSeries(plot, ctx, serie){
            var top = 0,left = 0, width = 100, height = 100,j;
            if(!serie.xaxis.options.font){ serie.xaxis.options.font = createFont(plot.getPlaceholder());}
            if (serie.rectangle.show) {
                series = serie;
                offset = plot.getPlotOffset();
                colors = createColors(opt,serie.data.length);
                sumRect = 0;
                for(j = 0; j < serie.data.length; j++){ sumRect += serie.data[j].data;}
                for(j = 0; j < serie.data.length; j++) {
                    var x,y,w,h,d,v;
                    v = serie.data[j];
                    d = serie.rectangle.directions[j % serie.rectangle.directions.length]; 
                    switch(d){
                        case "t":
                            x = left; y = top;
                            w = width; h = v.data / sumRect * 100 / width * 100;
                            top = top + h;height = height - h;
                            break;
                        case "b":
                            x = left; h = v.data / sumRect * 100 / width * 100;
                            w = width; y = top - h + height;
                            height = height - h;
                            break;
                        case "l":
                            x = left; y = top;
                            w = v.data / sumRect * 100 / height * 100; h = height;
                            left = left + w; width = width - w;
                            break;
                        case "r":
                            y = top; w = v.data / sumRect * 100 / height * 100;
                            x = left + width - w; h = height;
                            width = width - w;
                            break;
                        default:
                            x = left; y = top;
                            w = width; h = v.data / sumRect * 100 / width * 100;
                            top = top + h;
                            height = height - h;				    
                    }
                    var cx,cy,cw,ch,color;
                    cx = offset.left + serie.xaxis.p2c(x);
                    cy = offset.top + serie.yaxis.p2c(100 - y);
                    cw = serie.xaxis.p2c(w) - serie.xaxis.p2c(0);
                    ch = serie.yaxis.p2c(0) - serie.yaxis.p2c(h);
                    color = $.plot.JUMlib.data.getColor(
                        {ctx:ctx,serie:series,dataIndex:j,colors:colors,
                        left:cx,top:cy,height:ch,width:cw});
                    serie.data[j].pos = {x:cx,y:cy,w:cw,h:ch,color:color};
                    serie.rectangle.drawRectangle(ctx,serie,j);
                }
            }
        }
        function drawHoverRectangle(octx,serie,dataIndex){
            var d,c,pos;
            d = serie.data[dataIndex].pos;
            c = "rgba(255,255,255," + serie.rectangle.highlight.opacity + ")";
            pos = {x:d.x,y:d.y,w:d.w,h:d.h,color:c,dataPoint:d.dataPoint};
            serie.rectangle.drawRectangle(octx,serie,dataIndex);
        }
        function findNearbyItemRectangle(mouseX, mouseY,i,serie){
            var item = null;
            item = findNearbyItem(mouseX,mouseY,i,serie);        
            return item;
            function findNearbyItem(mouseX,mouseY,i,serie){
                var item = null;
                for(var j = 0; j < serie.data.length; j++){
                    var p = serie.data[j].pos;
                    if(between(mouseX,p.x,p.x + p.w)){
                        if(between(mouseY,p.y,p.y + p.h)){ item = [i,j];}
                    }
                }
                return item;
            }
        }
    }
    var between = $.plot.JUMlib.library.between;
    var createFont = $.plot.JUMlib.data.createFont;
    var createColors = $.plot.JUMlib.data.createColors;
    $.plot.plugins.push({
        init: init,
        options: options,
        name: pluginName,
        version: pluginVersion
    });
})(jQuery);