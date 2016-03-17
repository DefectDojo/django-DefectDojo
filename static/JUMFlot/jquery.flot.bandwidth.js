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

(function ($){
    "use strict";
    var pluginName = "bandwidth", pluginVersion = "0.5";
    var options ={
        series:{
            bandwidth:{
                active: false,
                show: false,
                fill: true,
                lineWidth: "4px",
                highlight: { opacity: 0.5 },
                drawBandwidth: drawBandwidthDefault
            }
        }
    };
    var replaceOptions = { series:{ lines: { show:false } } };
    var defaultOptions = { 
        series: {
            editMode: 'y',
            nearBy: {
                distance: 7,
                findItem: null,
                findMode: "circle",
                drawHover: null
            }
        }
    };
    function drawBandwidthDefault(ctx,bandwidth, x,y1,y2,color){
        ctx.beginPath();
        ctx.strokeStyle = color;
        ctx.lineWidth = bandwidth.barWidth;
        ctx.lineCap = "round";
        ctx.moveTo(x, y1);
        ctx.lineTo(x, y2);
        ctx.stroke();
    }	
    function init(plot){
        var offset = null, opt = null, series = null;
        plot.hooks.processOptions.push(processOptions);
        function processOptions(plot,options){
            if(options.series.bandwidth.active){
                $.extend(true,options,replaceOptions);
                $.plot.JUMlib.data.extendEmpty(options,defaultOptions);
                opt = options;
                plot.hooks.processRawData.push(processRawData);
                plot.hooks.drawSeries.push(drawSeries);
            }
        }
        function processRawData(plot,s,data,datapoints){
            if(s.bandwidth.show === true){
                s.nearBy.findItem = findNearbyItemBandwidth;
                s.nearBy.drawHover = drawHoverBandwidth;
            }
        }
        function drawSeries(plot, ctx, serie){
            if(serie.bandwidth.show){
                if(opt.series.bandwidth.debug.active === true) { series = serie;}
                if(typeof(serie.bandwidth.lineWidth) === 'string'){
                    serie.bandwidth.barWidth = parseInt(serie.bandwidth.lineWidth,0);
                    serie.nearBy.width = serie.bandwidth.barWidth;
                }
                else { 
                    var dp = serie.xaxis.p2c(serie.xaxis.min + serie.bandwidth.lineWidth) - serie.xaxis.p2c(serie.xaxis.min);
                    serie.bandwidth.barWidth = dp;
                    serie.nearBy.width = serie.bandwidth.lineWidth;
                }
                offset = plot.getPlotOffset();
                for (var j = 0; j < serie.data.length; j++){drawBandwidth(ctx,serie,j,serie.color);}
            }
        }
        function drawBandwidth(ctx,serie,j,color){
            var x,y1,y2,data;
            if(j.length){ data = serie.data[j[0]];} else{ data = serie.data[j];}
            x = offset.left + serie.xaxis.p2c(data[0]);
            y1 = offset.top + serie.yaxis.p2c(data[1]);
            y2 = offset.top + serie.yaxis.p2c(data[2]);
            serie.bandwidth.drawBandwidth(ctx,serie.bandwidth, x,y1,y2,color);
        }
        function findNearbyItemBandwidth(mouseX, mouseY,i,serie){
            var item = null;
            if(opt.series.justEditing){
                if(opt.series.justEditing[1].seriesIndex === i){item = findNearbyItemEdit(mouseX,mouseY,i,serie);}
            }
            else{ 
                if(opt.grid.editable){ item = findNearbyItemForEdit(mouseX,mouseY,i,serie);}
                else{item = findNearbyItem(mouseX,mouseY,i,serie);}			  
            }
            return item;
            function findNearbyItemEdit(mouseX,mouseY,i,serie){
                var item = null;
                var j = opt.series.justEditing[1].dataIndex;
                if(j.length){ item = [i,j];}else{item = [i,j];}
                return item;
            }
            function findNearbyItemForEdit(mouseX,mouseY,i,serie){
                var item = null;
                if(serie.bandwidth.show){
                    for(var j = 0; j < serie.data.length; j++){
                        var x,y1,y2,dataitem;
                        dataitem = serie.data[j];
                        x = serie.xaxis.p2c(dataitem[0]) - serie.bandwidth.barWidth / 2;
                        y1 = serie.yaxis.p2c(dataitem[1]) - serie.bandwidth.barWidth / 2;
                        y2 = serie.yaxis.p2c(dataitem[2]) - serie.bandwidth.barWidth / 2;
                        if(between(mouseX,x,(x+serie.bandwidth.barWidth))){
                            if(between(mouseY,y1,y2)){item = [i,j]; serie.editMode = 'x'; serie.nearBy.findMode = 'horizontal';}
                            if(between(mouseY,y1,(y1 + serie.bandwidth.barWidth))){ item = [i,[j,1]]; serie.editMode='y'; serie.nearBy.findMode = 'vertical';}
                            if(between(mouseY,y2,(y2 + serie.bandwidth.barWidth))){ item = [i,[j,2]]; serie.editMode='y';serie.nearBy.findMode = 'vertical';}
                        }
                    }
                }
                return item;
            }
            function findNearbyItem(mouseX,mouseY,i,serie){
                var item = null;
                if(serie.bandwidth.show){
                    for(var j = 0; j < serie.data.length; j++){
                        var x,y1,y2,dataitem;
                        dataitem = serie.data[j];
                        x = serie.xaxis.p2c(dataitem[0]) - serie.bandwidth.barWidth / 2;
                        y1 = serie.yaxis.p2c(dataitem[1]);
                        y2 = serie.yaxis.p2c(dataitem[2]);
                        if(between(mouseX,x,(x + serie.bandwidth.barWidth))){
                            if(between(mouseY,y1,y2)){ item = [i,j]; }
                        }
                    }
                }
                return item;
            }
        }
        function drawHoverBandwidth(octx,serie,dataIndex){
            octx.save();
            octx.translate(-offset.left,-offset.top);
            var c = "rgba(255,255,255," + serie.bandwidth.highlight.opacity + ")";
            drawBandwidth(octx,serie,dataIndex,c);
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