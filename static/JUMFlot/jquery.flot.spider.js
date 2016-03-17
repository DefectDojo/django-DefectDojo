/* * The MIT License

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
    var pluginName = "spider", pluginVersion = "0.6";
    var options ={
        series:{
            spider:{
                active: false,
                show: false,
                spiderSize: 0.8,
                lineWidth: 3,
                lineStyle: "rgba(0,0,0,0.5)",
                pointSize: 6,
                scaleMode: "leg",
                legMin: null,
                legMax: null,
                connection: { width: 4 },
                highlight: { opacity: 0.5, mode: "point" },
                legs: {
                    font: "20px Times New Roman",
                    fillStyle: "Black",
                    legScaleMin: 0.95,
                    legScaleMax: 1.05,
                    legStartAngle: 0 
                }
            }
        }
    };
    var defaultOptions = {
        series:{
            editMode: 'xy',    //could be none, x, y, xy, v
            nearBy:{
                distance: 6,
                findItem: null,
                findMode: "circle",
                drawEdit: null,
                drawHover: null
            }
        },
        grid:{mode:"radar"}
    };
    var replaceOptions = {
        grid:{
            show:false,
            tickColor: "rgba(0,0,0,0.15)",
            ticks: 5
        }
    };
    function init(plot){
        var maxRadius = null, centerLeft = null, opt = null, centerTop = null, series = null,data; 
        plot.hooks.processOptions.push(processOptions);
        function processOptions(plot,options){
            if(options.series.spider.active){
                $.extend(true,options,replaceOptions);
                $.plot.JUMlib.data.extendEmpty(options,defaultOptions);
                opt = options;
                plot.hooks.processRawData.push(processRawData);
                plot.hooks.draw.push(draw);
            }
        }
        function processRawData(plot,s,data,datapoints){
            if(s.spider.show === true){
                s.nearBy.drawEdit = drawEditSpider;
                s.nearBy.findItem = findNearbyItemSpider;
                s.nearBy.drawHover = drawHoverSpider;
            }
        }
        function draw(plot, ctx){
            data = plot.getData();
            opt = plot.getOptions();
            if(opt.series.spider.debug.active === true) { series = data[0]; }
            clear(ctx);
            setupspider(ctx);
            calculateRanges();
            drawspider(ctx,opt.grid);
        }
        function calculateRanges(){
            var ranges = [],j;
            if (data[0].spider.scaleMode === 'leg'){
                for (j = 0; j < data[0].data.length; j++){ ranges.push(calculateItemRanges(j)); }
            }
            else{
                var range = calculateRange();
                for(j = 0; j < data[0].data.length; j++){ ranges.push(range); }
            }
            data.ranges = ranges;
        }
        function calculateItemRanges(j){
            var min = Number.POSITIVE_INFINITY, max = Number.NEGATIVE_INFINITY;
            for(var i = 0; i < data.length; i++){
                min = Math.min(min,data[i].data[j][1]);
                max = Math.max(max,data[i].data[j][1]);
            } 
            min = min * data[0].spider.legs.legScaleMin;
            max = max * data[0].spider.legs.legScaleMax;
            if(opt.series.spider.legMin){ min = opt.series.spider.legMin;}
            if(opt.series.spider.legMax){ max = opt.series.spider.legMax;}
            return {min: min, max:max, range: max - min};
        }
        function calculateRange(){
            var min = Number.POSITIVE_INFINITY, max = Number.NEGATIVE_INFINITY;
            for(var j = 0; j < data[0].data.length; j++){
                for(var i = 0; i < data.length; i++){
                    min = Math.min(min,data[i].data[j][1]);
                    max = Math.max(max,data[i].data[j][1]);
                }
            }
            min = min * data[0].spider.legs.legScaleMin;
            max = max * data[0].spider.legs.legScaleMax;
            if(opt.series.spider.legMin){ min = opt.series.spider.legMin;}
            if(opt.series.spider.legMax){ max = opt.series.spider.legMax;}
            return {min: min, max:max, range: max - min};			
        }
        function clear(ctx){
            ctx.clearRect(0,0,ctx.canvas.width,ctx.canvas.height);
        }
        function setupspider(ctx){
            maxRadius =  Math.min(ctx.canvas.width,ctx.canvas.height)/2 * data[0].spider.spiderSize;
            centerTop = (ctx.canvas.height/2);
            centerLeft = centerTop;
        }
        function drawspiderPoints(ctx,cnt,serie,opt){
            for(var j = 0; j < serie.data.length; j++) { drawspiderPoint(ctx,cnt,serie,j,opt); }
        }
        function drawspiderPoint(ctx,cnt,serie,j,c){
            var pos;
            var d = calculatePosition(serie,data.ranges,j);
            pos = calculateXY(cnt,j,d);
            ctx.beginPath();
            ctx.lineWidth = 1;
            ctx.fillStyle = c;
            ctx.strokeStyle = c;
            ctx.arc(pos.x,pos.y,serie.spider.pointSize,0,Math.PI * 2,true);
            ctx.closePath();
            ctx.fill();
        }
        function drawspiderConnections(ctx,cnt,serie,c,fill){
            var pos,d;
            if(!fill){ fill = false;}
            ctx.beginPath();
            ctx.lineWidth = serie.spider.connection.width;
            ctx.strokeStyle = c;
            ctx.fillStyle = c;
            d = calculatePosition(serie,data.ranges,0);
            pos = calculateXY(cnt,0,d);
            ctx.moveTo(pos.x,pos.y);
            for(var j = 1;j < serie.data.length; j++){
                d = calculatePosition(serie,data.ranges,j);
                pos = calculateXY(cnt,j,d);
                ctx.lineTo(pos.x,pos.y);
            }
            d = calculatePosition(serie,data.ranges,0);
            pos = calculateXY(cnt,0,d);
            ctx.lineTo(pos.x,pos.y);
            if(fill === true){ ctx.fill();} 
            else { if(serie.spider.fill === true){ ctx.fill();} else{ ctx.stroke();} }
        }
        function drawspider(ctx, opt){
            var cnt = data[0].data.length,i;
            for(i = 0;i < data.length; i++){ drawspiderConnections(ctx,cnt,data[i],data[i].color); }
            for(i = 0;i < data.length; i++){ drawspiderPoints(ctx,cnt,data[i],data[i].color); }
            drawGrid(ctx, opt);
            function drawGridRadar(ctx,opt){
                ctx.lineWidth = 1;
                ctx.strokeStyle = opt.tickColor;
                for (var i = 1; i <= opt.ticks; i++) {
                    ctx.beginPath();
                    ctx.arc(centerLeft, centerTop, maxRadius / opt.ticks * i, 0, Math.PI * 2, true);
                    ctx.closePath();
                    ctx.stroke();
                }
                // based on a patch from Thomasz Janik
                var startPoint = null;
                var breakPoint = null;
                for (var j = 0; j < cnt; j++){	
                    if(startPoint === null){
                        startPoint = calculateXY(cnt,j,100);
                        breakPoint = calculateXY(cnt,Math.floor(cnt/4),100);
                    }
                    drawspiderLine(ctx, j);
                    drawspiderLeg(ctx,j,startPoint,breakPoint);
                }
            }
            function drawGridSpider(ctx,opt){
                var i,j;
                ctx.linewidth = 1;
                ctx.strokeStyle = opt.tickColor;
                for(i = 0; i<= opt.ticks; i++){
                    var pos = calculateXY(cnt,0,100 / opt.ticks * i);
                    ctx.beginPath();
                    ctx.moveTo(pos.x, pos.y);
                    for(j = 1; j < cnt; j++){
                        pos = calculateXY(cnt,j,100 / opt.ticks * i);
                        ctx.lineTo(pos.x, pos.y);
                    }
                    ctx.closePath();
                    ctx.stroke();
                }
                var startPoint = null;
                var breakPoint = null;
                for (j = 0; j < cnt; j++) {
                    if(startPoint === null){
                        startPoint = calculateXY(cnt,j,100);
                        breakPoint = calculateXY(cnt,Math.floor(cnt/4),100);
                    }
                    drawspiderLine(ctx,j);
                    drawspiderLeg(ctx,j,startPoint,breakPoint);
                }
            }
            function drawGrid(ctx, opt){
                switch(opt.mode){
                    case "radar":
                        drawGridRadar(ctx,opt);
                        break;
                    case "spider":
                        drawGridSpider(ctx,opt);
                        break;
                    default:
                        drawGridRadar(ctx,opt);
                        break;
                }
            }
            function drawScale(ctx,opt){
                if(opt.series.spider.scaleMode !== "leg"){
                    for(var i = 0; i <= opt.ticks; i++){	
                    }
                }
            }
            function drawspiderLine(ctx, j){
                var pos;
                ctx.beginPath();
                ctx.lineWidth = options.series.spider.lineWidth;
                ctx.strokeStyle = options.series.spider.lineStyle;
                ctx.moveTo(centerTop, centerLeft);
                pos = calculateXY(cnt,j,100);
                ctx.lineTo(pos.x, pos.y);
                ctx.stroke();
            }
            function drawspiderLeg(ctx,j,startPoint,breakPoint,gridColor){
                var pos,metrics,extraX,extraY;
                pos = calculateXY(cnt,j,100);
                ctx.font = data[0].spider.legs.font;
                ctx.fillStyle = data[0].spider.legs.fillStyle;
                // based on patch created by Thomasz Janik
                metrics = ctx.measureText(data[0].spider.legs.data[j].label);
                if(pos.y > startPoint.y){ extraY = 15;} else{ extraY = -15;}
                if(between(pos.y,startPoint.y+10,startPoint.y-10)){ extraY = 0;}
                if(pos.x < breakPoint.x){ extraX = (metrics.width*-1)-metrics.width/2;}else{ extraX = 0;}
                if(between(pos.x,startPoint.x+10,startPoint.x-10)) { extraX = metrics.width/2; }
                ctx.fillText(data[0].spider.legs.data[j].label, pos.x + extraX, pos.y + extraY);
            }
        }
        function calculatePosition(serie,ranges,j,v){
            var p;
            if(v){ p = ((v - ranges[j].min) / ranges[j].range * 100); }
            else{
                p = Math.max(Math.min(serie.data[j][1],ranges[j].max),ranges[j].min);
                p = (p - ranges[j].min) / ranges[j].range * 100;
            }
            return p; 
        }
        function calculateXY(cnt,j,d){
            var x,y,s;
            s = 2 * Math.PI * opt.series.spider.legs.legStartAngle / 360;
            x = centerLeft + Math.round(Math.cos(2 * Math.PI / cnt * j + s) * maxRadius * d / 100);
            y = centerTop + Math.round(Math.sin(2 * Math.PI / cnt * j + s) * maxRadius * d / 100);
            return {x: x, y: y};
        }
        function calculateFromCenter(mx,my){
            var d;
            d = (mx - centerLeft) * (mx - centerLeft) + (my - centerTop) * (my - centerTop);
            d = Math.sqrt(d);
            d = d / maxRadius * 100;
            return d;
        }
        function calculateValue(i,d){
            var v,range = data.ranges[i];
            v = range.min + range.range / 100 * d; 
            return v;
        }
        function findNearbyItemSpider(mouseX,mouseY,i,serie){
            var item = null;
            if(opt.series.justEditing){
                if(opt.series.justEditing[1].seriesIndex === i){ item = findNearbyEdit(mouseX,mouseY,i,serie); }
            }
            else { item = findNearby(mouseX,mouseY,i,serie); }
            return item;
            function findNearby(mouseX,mouseY,i,serie){
                var j,pos,dx,dy,dist,item = null;
                var cnt = serie.data.length;
                for(j = 0; j < cnt; j++){
                    pos = calculateXY(cnt,j,calculatePosition(serie,data.ranges,j));
                    dx = Math.abs(pos.x - mouseX);
                    dy = Math.abs(pos.y - mouseY);
                    dist = Math.sqrt(dx * dx + dy * dy); 
                    if (dist <= serie.nearBy.distance) {item = [i,j]; }
                }
                return item;
            }
            function findNearbyEdit(mouseX,mouseY,i,serie) { 
                var v,dx,dy,dist,pos,d,item = null;
                var cnt = serie.data.length,j = opt.series.justEditing[1].dataIndex;
                d = calculateFromCenter(mouseX,mouseY); 
                v = calculateValue(j,d);
                pos = calculateXY(cnt,j,d);
                dx = Math.abs(pos.x - mouseX);
                dy = Math.abs(pos.y - mouseY);
                dist = Math.sqrt(dx * dx + dy * dy); 
                if (dist <= serie.spider.pointSize) { item = [i,j,v,0]; }
                return item;        
            }
        }
        function drawEditSpider(octx,x,y,serie){
            octx.beginPath();
            octx.lineWidth = 1;
            var c = "rgba(255, 0, 0, " + serie.spider.highlight.opacity + ")";
            octx.fillStyle = c;
            octx.strokeStyle = c;
            var v = calculatePosition(serie,data.ranges,opt.series.justEditing[1].dataIndex,opt.series.justEditing[0].value);
            var pos = calculateXY(serie.data.length,opt.series.justEditing[1].dataIndex,v);
            octx.arc(pos.x,pos.y,opt.series.spider.pointSize,0,Math.PI * 2,true);
            octx.closePath();
            octx.fill();
        }
        function drawHoverSpider(octx,serie,dataIndex){
            if(!serie.justEditing){
                var c = "rgba(255, 255, 255, " + serie.spider.highlight.opacity + ")",
                    cnt = serie.data.length;
                switch(serie.spider.highlight.mode){
                    case "point":
                        drawspiderPoints(octx,cnt,serie,c);
                        break;
                    case "line":
                        drawspiderConnections(octx,cnt,serie,c,false);
                        break;
                    case "area":
                        drawspiderConnections(octx,cnt,serie,serie.color,true);
                        break;
                    default:
                        break;
                }
            }
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
