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
    var pluginName = "pyramids", pluginVersion = "0.2";
    var options = {
        series: { 
            pyramids: {
                active: false,
                show: false,
                mode: "pyramid",
                fill: true,
                highlight: { opacity: 0.5 },
                label: {
                    show: false,
                    align:"center",
                    font: "20px Times New Roman",
                    fillStyle: "Black"
                }
            }
        }
    };
    var defaultOptions = {
        series:{        
            nearBy:{
                distance: 6,
                findItem: null,
                findMode: "circle",
                drawHover: null
            }
        }
    };
    var replaceOptions = {grid:{show:false} };
    function init(plot) {
        var  opt = null,offset = null,series = null,dataHeight = null, dataMax,centerX,canvasHeight,canvasWidth;
        plot.hooks.processOptions.push(processOptions);
        function processOptions(plot,options){
            if (options.series.pyramid.active===true){	
                $.extend(true,options,replaceOptions);
                $.plot.JUMlib.data.extendEmpty(options,defaultOptions);
                opt = options;
                plot.hooks.processRawData.push(processRawData);
                plot.hooks.drawSeries.push(drawSeries);
            }
        }
        function processRawData(plot,s,data,datapoints){
            if(s.pyramid.show === true){
                s.nearBy.findItem = findNearbyItemPyramid;
                s.nearBy.drawHover = drawHoverPyramid;
            }
        }
        function drawSeries(plot, ctx,serie){
            if (serie.pyramid.show) {
                if(opt.series.pyramid.debug.active === true) { series = serie;}
                offset = plot.getPlotOffset();
                dataMax = serie.data[0].value;
                canvasHeight = ctx.canvas.height;
                canvasWidth = ctx.canvas.width;
                dataHeight = ctx.canvas.height / serie.data.length;
                centerX = ctx.canvas.width / 2;
                for (var j = 0; j < serie.data.length; j++) {drawItem(ctx,serie,j,opt.colors[j]);}
            }
        }
        function drawItem(ctx,serie,j,c){
            var lowWidth,highWidth,lowY;
            lowWidth = serie.data[j].value * ctx.canvas.width / dataMax;
            lowY = ctx.canvas.height - (dataHeight * j);
            if((j+1)==serie.data.length){ highWidth = 0;} else{ highWidth = serie.data[j+1].value * ctx.canvas.width / dataMax;}
            if ($.isFunction(serie.pyramid.mode)) {
                serie.pyramid.mode(ctx,serie,centerX, lowY, lowWidth, dataHeight, highWidth, c);
            }
            else {
                switch (serie.pyramid.mode) {
                    case "pyramid":
                        drawPyramid(ctx, serie, lowY, lowWidth, dataHeight, highWidth, c);
                        break;
                    case "slice":
                        drawSlice(ctx, serie, lowY, lowWidth, dataHeight, highWidth, c);
                        break;
                    default:
                        drawPyramid(ctx, serie, lowY, lowWidth, dataHeight, highWidth, c);
                }
            }
            if(serie.pyramid.label.show===true){ drawLabel(ctx,serie,serie.data[j],lowY - dataHeight / 2);}
        }
        function drawLabel(ctx,serie,data,posY){
            var posX;
            ctx.font = serie.pyramid.label.font;
            ctx.fillStyle = serie.pyramid.label.fillStyle;
            var metrics = ctx.measureText(data.label);
            switch(serie.pyramid.label.align) {
                case "center":
                    posX = ctx.canvas.width / 2 - metrics.width / 2;
                    break;
                case "left":
                    posX = 0;
                    break;
                case "right":
                    posX = ctx.canvas.width - metrics.width;
                    break;	 								
                default:
                    posX = ctx.canvas.width - metrics.width;
            }
            ctx.fillText(data.label, posX,posY);
        }
        function drawPyramid(ctx,serie,lowY,lowWidth,dataHeight,highWidth,c){
            ctx.beginPath();
            ctx.lineWidth = 1;
            ctx.fillStyle = c;
            ctx.strokeStyle = c;
            ctx.moveTo(centerX - lowWidth / 2,lowY);
            ctx.lineTo(centerX + lowWidth / 2,lowY);
            ctx.lineTo(centerX + highWidth / 2,lowY - dataHeight);
            ctx.lineTo(centerX - highWidth / 2,lowY - dataHeight);
            ctx.closePath();
            ctx.fill();
        }
        function drawSlice(ctx,serie,lowY,lowWidth,dataHeight,highWidth,c){
            var centerY = lowY - dataHeight/2;
            ctx.save();
            ctx.beginPath();
            ctx.lineWidth = 1;
            ctx.fillStyle = c;
            ctx.strokeStyle = c;
            ctx.translate(centerX - lowWidth / 2,centerY - dataHeight/2);
            ctx.scale(lowWidth / 2,dataHeight/2);
            ctx.arc(1,1,1,0,2 * Math.PI,false);
            ctx.closePath();
            ctx.fill();
            ctx.restore();
        }
        function findNearbyItemPyramid(mouseX, mouseY,i,serie){
            var item = null;
            item = findNearby(mouseX,mouseY,i,serie);
            return item;
            function findNearby(mouseX,mouseY,i,serie){
                var item = null;
                var ln = Math.floor((canvasHeight - mouseY) / dataHeight);
                if(between(ln,0,serie.data.length-1)){
                    var w = serie.data[ln].value * canvasWidth / dataMax;
                    if (between(mouseX,centerX - w / 2,centerX + w / 2)===true) { item = [i,ln];}
                }
                return item;
            }
        }
        function drawHoverPyramid(octx,serie,dataIndex){
            octx.save();
            octx.translate(-offset.left,-offset.top);
            var c = "rgba(255,255,255," + serie.pyramid.highlight.opacity + ")";
            drawItem(octx,serie,dataIndex,c);
            octx.restore();
        }
    }
    var between = $.plot.JUMlib.library.between;
    $.plot.plugins.push({
        init: init,
        options: options,
        name: pluginName,
        version: pluginVersion
    });
})(jQuery);