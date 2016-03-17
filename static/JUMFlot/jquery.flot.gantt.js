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
    var pluginName = "gantt", pluginVersion = "0.3";
    var options = {
        series: {
            gantt: {
                active: false,
                show: false,
                connectSteps: { show: false, lineWidth:2, color:"rgb(0,0,0)" },
                barHeight: 0.6,
                highlight: { opacity: 0.5 },
                drawstep: drawStepDefault
            }
        }
    };
    var replaceOptions = { series:{ lines: { show:false } } };
    var defaultOptions = {
        series:{
            editMode: 'y',    //could be none, x, y, xy, v
            nearBy:{
                distance: 6,
                findItem: null,
                findMode: "circle",
                drawHover: null
            }
        }   
    };
    function drawStepDefault(ctx,series,data,x,y,x2,color, isHighlight){
        if(isHighlight === false){
            ctx.beginPath();
            ctx.lineWidth = series.gantt.barheight;
            ctx.strokeStyle = "rgb(0,0,0)";
            ctx.moveTo(x, y);
            ctx.lineTo(x2, y);
            ctx.stroke();
        }
        ctx.beginPath();
        ctx.strokeStyle = color;
        ctx.lineWidth = series.gantt.barheight - 2;
        ctx.lineCap = "butt";
        ctx.moveTo(x + 1, y);
        ctx.lineTo(x2 - 1, y);
        ctx.stroke();
    }
    function init(plot) {
        var offset = null, opt = null, series = null,canvas,target,axes,data;
        plot.hooks.processOptions.push(processOptions);
        function processOptions(plot,options){
            if (options.series.gantt.active){
                $.extend(true,options,replaceOptions);
                $.plot.JUMlib.data.extendEmpty(options,defaultOptions);
                opt = options;
                plot.hooks.processRawData.push(processRawData);
                plot.hooks.draw.push(draw);
            }
        }
        function processRawData(plot,s,data,datapoints){
            if(s.gantt.show === true){
                s.nearBy.findItem = findNearbyItemGantt;
                s.nearBy.drawHover = drawHoverGantt;
            }
        }		
        function draw(plot, ctx){
            var serie;
            canvas = plot.getCanvas();
            target = $(canvas).parent();
            axes = plot.getAxes();           
            offset = plot.getPlotOffset();
            data = plot.getData();
            for (var i = 0; i < data.length; i++){
                serie = data[i];
                serie.gantt.barheight = axes.yaxis.p2c(1) / (axes.yaxis.max - axes.yaxis.min) * serie.gantt.barHeight;
                if (serie.gantt.show) {
                    series = serie;
                    for (var j = 0; j < serie.data.length; j++){drawData(ctx,serie, serie.data[j], serie.color,false); }
                    if(serie.gantt.connectSteps.show){ drawConnections(ctx,serie); }
                }
            }
        }
        function drawData(ctx,series,data,color,isHighlight){
            var x,y,x2;
            x = offset.left + axes.xaxis.p2c(data[0]);
            x = Math.min(Math.max(offset.left,x),offset.left + plot.width());
            y = offset.top + axes.yaxis.p2c(data[1]);
            x2 = offset.left + axes.xaxis.p2c(data[2]);
            x2 = Math.min(Math.max(x2,offset.left),offset.left + plot.width());
            if(x2 > offset.left || x > offset.left){
                if (x < (offset.left + plot.width()) || x2 < (offset.left + plot.width())){
                    if (data.length === 4) {drawStepDefault(ctx, series, data, x, y, x2, color, isHighlight);}
                    else{ series.gantt.drawstep(ctx,series,data,x,y,x2,color,isHighlight);}
                }
            }
        }
        function drawConnections(ctx,series){
            for(var i = 0; i < series.data.length; i++){
                for(var j = 0; j < series.data.length; j++){
                    if(series.data[i][2] == series.data[j][0]){
                        var x = offset.left + axes.xaxis.p2c(series.data[i][2]),
                            y = offset.top + axes.yaxis.p2c(series.data[i][1]),
                            y2 = offset.top + axes.yaxis.p2c(series.data[j][1]);
                        drawConnection(ctx,x,y,y2,series.gantt.connectSteps.lineWidth,series.gantt.connectSteps.color);		   
                    }
                }
            }
        }
        function drawConnection(ctx,x,y,y2,lineWidth,color){
            ctx.beginPath();
            ctx.lineWidth = lineWidth;
            ctx.strokeStyle = color;
            ctx.moveTo(x, y);
            ctx.lineTo(x, y2);
            ctx.stroke();
        }
        function findNearbyItemGantt(mouseX, mouseY,i,serie){
            var item = null;
            if(opt.series.justEditing){
                if(opt.series.justEditing[1].seriesIndex === i){item = findNearbyItemEdit(mouseX,mouseY,i,serie);}
            }
            else{ 
                if(opt.grid.editable){ item = findNearbyItemForEdit(mouseX,mouseY,i,serie);}
                else{ item = findNearbyItem(mouseX,mouseY,i,serie);}        
            }
            return item;
            function findNearbyItem(mouseX,mouseY,i,serie){
                var item = null;
                if(serie.gantt.show){
                    for(var j = 0; j < serie.data.length; j++){
                        var dataitem = serie.data[j];
                        var dx = serie.xaxis.p2c(dataitem[0]),dx2 = serie.xaxis.p2c(dataitem[2]),
                        dy = Math.abs(serie.yaxis.p2c(dataitem[1]) - mouseY);
                        if(dy <= serie.gantt.barheight / 2){ if(between(mouseX,dx,dx2)){ item = [i,j]; } }
                    }
                }
                return item;
            }
            function findNearbyItemForEdit(mouseX,mouseY,i,serie){
                var item = null;
                if(serie.gantt.show){
                    for(var j = 0; j < serie.data.length; j++){
                        var dataitem = serie.data[j];
                        var dx = serie.xaxis.p2c(dataitem[0]),dx2 = serie.xaxis.p2c(dataitem[2]),
                            dy = Math.abs(serie.yaxis.p2c(dataitem[1]) - mouseY);
                        if(dy <= serie.gantt.barheight / 2){
                            if(between(mouseX,dx,dx2)){ item = [i,j]; serie.editMode = 'y'; serie.nearBy.findMode = 'vertical';serie.nearBy.width = dataitem[2]-dataitem[0];}
                            if(between(mouseX,dx,dx + serie.nearBy.distance)) { item = [i,[j,1]];serie.editMode = 'x'; serie.nearBy.findMode = 'horizontal'; }
                            if(between(mouseX,dx2,dx2 + serie.nearBy.distance)) { item = [i,[j,2]];serie.editMode = 'x'; serie.nearBy.findMode = 'horizontal'; }
                        } 
                    } 
                }
                return item;
            }
            function findNearbyItemEdit(mouseX,mouseY,i,serie){
                var item = null;
                var j = opt.series.justEditing[1].dataIndex;
                var dataitem = serie.data[j];
                if(j.length){item = [i,j];}else{item = [i,j];}
                return item;		   
            }
        }
        function drawHoverGantt(octx,serie,dataIndex){
            var data;
            octx.save();
            octx.translate(-offset.left,-offset.top);
            var c = "rgba(255,255,255, " + serie.gantt.highlight.opacity + ")";
            if(dataIndex.length){ data = serie.data[dataIndex[0]];} else{ data = serie.data[dataIndex];}
            drawData(octx,serie,data,c,true);
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
