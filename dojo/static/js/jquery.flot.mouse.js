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
    var options = { 
        series: {
            editable: null,
            editMode: 'xy',    //could be none, x, y, xy, v
            justEditing: null,
            justMoving: null,
            autoSet : false,
            nearBy:{
                distance: 6,
                findItem: findNearbyItemDefault,
                findMode: "circle",
                drawEdit: drawEditDefault,
                drawHover: drawHoverDefault
            }
        },
        grid:  { editable : false }
    };
    function init(plot) {
        var opt = null, evtHolder = null, plotOffset = null, placeHolder = null;
        plot.hooks.bindEvents.push(bindEvents);        
        function bindEvents(plot, eventHolder) { 
            opt = plot.getOptions();
            evtHolder = eventHolder;
            plotOffset = plot.getPlotOffset();
            placeHolder = plot.getPlaceholder();
            if (opt.grid.editable || opt.grid.clickable || opt.grid.hoverable) {
                evtHolder.mousedown(onMouseDown);
                evtHolder.mouseup(onMouseUp);
                evtHolder.mousemove(onMouseMove);
                evtHolder.click(onMouseClick);
            }
        }
        function onMouseClick(e){
            var positem = getMousePosition(e);
            if(positem[1]){
                var s = positem[1].series;
                if(s.points.show === false && (!s.lines.show || s.lines.show === false) && s.bars.show === false){
                    placeHolder.trigger("plotclick",positem);
                }
            }
        }
        function onMouseDown(e) {
            if (opt.grid.editable){
                var positem = getMousePosition(e);
                if(positem[1]){
                    var v = null;
                    if(positem[1].series.editable){
                        if(positem[1].dataIndex.length){ v = positem[1].series.data[positem[1].dataIndex[0]]; }
                        else{ v = positem[1].series.data[positem[1].dataIndex]; }
                        switch(positem[1].series.editMode){
                            case "x":
                                positem[0].y = v[1];
                                positem[0].y1 = v[1];
                                break;
                            case "y":
                                positem[0].x = v[0];
                                positem[0].x1 = v[0];
                                break;
                        }
                        opt.series.justEditing = positem;
                    }
                    placeHolder.trigger("plotdown",positem);
                }
                placeHolder.css('cursor', 'auto');
            }    
        }        
        function onMouseUp(e){
            if (opt.series.justEditing){
                placeHolder.trigger("plotup",opt.series.justEditing);
                placeHolder.trigger("datadrop",opt.series.justEditing);
                var s = opt.series.justEditing[1].series;
                if(s.autoEdit === true){ var p = opt.series.justEditing[0]; s.data[s.dataIndex] = [p.x1,p.y1]; }
            }
            opt.series.justEditing = null;
            plot.triggerRedrawOverlay();
        }
        function onMouseMove(e) {
            var i; 
            var positem = getMousePosition(e);
            if (opt.series.justEditing) { 
                i = opt.series.justEditing[1].seriesIndex;        
                switch(plot.getData()[i].editMode){
                    case "none":
                        break;
                    case "x":
                        opt.series.justEditing[0].x = positem[0].x;
                        opt.series.justEditing[0].x1 = positem[0].x1;
                        opt.series.justEditing[0].pageX = positem[0].pageX;
                        break;
                    case "y":
                        opt.series.justEditing[0].y = positem[0].y;
                        opt.series.justEditing[0].y1 = positem[0].y1;
                        opt.series.justEditing[0].pageY = positem[0].pageY;
                        break;
                    case "v":
                        if(positem[1]){
                            opt.series.justEditing[0] = positem[0];
                            opt.series.justEditing[0].value = positem[1].value;
                        }
                        break;
                    case "xy":
                        opt.series.justEditing[0] = positem[0];
                        break;
                    default:
                        opt.series.justEditing[0] = positem[0];
                }
            }
            else{
                if(positem[1]){
                    opt.series.justMoving = positem;
                    i = positem[1].seriesIndex;        
                    switch(positem[1].series.editMode){
                        case "x":
                            placeHolder.css('cursor', 'col-resize');
                            break;
                        case "y":
                            placeHolder.css('cursor', 'row-resize');
                            break;
                        default:
                            placeHolder.css('cursor', 'crosshair');
                    }
                    var s = positem[1].series;
                    if(s.points.show === false && (!s.lines.show || s.lines.show === false) && s.bars.show === false){
                        placeHolder.trigger("plothover",positem);
                    }
                }
                else { placeHolder.css('cursor', 'auto'); opt.series.justMoving = null;}  
            }   
            plot.triggerRedrawOverlay();                
        }
        function getMousePosition(e){
            var pos, item = null, offset = evtHolder.offset();
            var canvasX = e.pageX - offset.left - plotOffset.left,
            canvasY = e.pageY - offset.top - plotOffset.top;
            pos = plot.c2p({ left: canvasX, top: canvasY });
            pos.pageX = e.pageX;
            pos.pageY = e.pageY;
            item = findNearbyItem(canvasX,canvasY);
            if (item) {
                item.pageX = parseInt(item.series.xaxis.p2c(item.datapoint[0]) + offset.left + plot.getPlotOffset().left,0);
                item.pageY = parseInt(item.series.yaxis.p2c(item.datapoint[1]) + offset.top + plot.getPlotOffset().top,0);
            }      
            return [pos,item];
        }
        function findNearbyItem(mouseX, mouseY){
            var item = null,v,i,j,ps;
            for(i = 0; i < plot.getData().length; i++){
                var s = plot.getData()[i];
                if(s.nearBy.findItem !== null){ item = s.nearBy.findItem(mouseX, mouseY, i, s);}
                if(item){ break;}
            }
            if (item) {
                i = item[0],j = item[1],ps = plot.getData()[i].datapoints.pointsize;
                if(item.length > 2){ v = item[2];} 
                var dp = plot.getData()[i].datapoints.points.slice(j * ps, (j + 1) * ps);              
                var r = { datapoint: dp,
                    dataIndex: j,series: plot.getData()[i],seriesIndex: i,value: v };
                return r;
            }
            return null;
        }
        plot.hooks.drawOverlay.push(drawOverlay);
        function drawOverlay(plot,octx){
            var serie,x,y;
            octx.save();
            octx.clearRect(0, 0, plot.getPlaceholder().width, plot.getPlaceholder().height);
            octx.translate(plot.getPlotOffset().left, plot.getPlotOffset().top);
            if(opt.series.justEditing){
                serie = plot.getData()[opt.series.justEditing[1].seriesIndex],
                x = opt.series.justEditing[0].x1,y = opt.series.justEditing[0].y1;
                if(serie.nearBy.drawEdit){ serie.nearBy.drawEdit(octx,x,y,serie);}
            }
            else if(opt.series.justMoving){
                serie = plot.getData()[opt.series.justMoving[1].seriesIndex];
                if(serie.nearBy.drawHover){ serie.nearBy.drawHover(octx,serie,opt.series.justMoving[1].dataIndex);}
            }
            octx.restore(); 
        }
    }
    function findNearbyItemDefault(mouseX,mouseY,i,serie) {
        // this is copied more or less(more more than less) from jquery.flot.js
        var maxDistance = serie.nearBy.distance,
        smallestDistance = maxDistance * maxDistance + 1,
        item = null,j,x,y,dx,dy,dist;
        var axisx = serie.xaxis,axisy = serie.yaxis,
        points = serie.datapoints.points,ps = serie.datapoints.pointsize,
        mx = axisx.c2p(mouseX),my = axisy.c2p(mouseY),
        maxx = maxDistance / axisx.scale,maxy = maxDistance / axisy.scale;
        if (axisx.options.inverseTransform){ maxx = Number.MAX_VALUE;}
        if (axisy.options.inverseTransform){ maxy = Number.MAX_VALUE;}
        for (j = 0; j < points.length; j += ps) {
            x = points[j];
            y = points[j + 1];
            if (x === null){ continue;}               
            switch(serie.nearBy.findMode){
                case "circle":
                    if (x - mx > maxx || x - mx < -maxx){ continue;}
                    if (y - my > maxy || y - my < -maxy){ continue;}
                    dx = Math.abs(axisx.p2c(x) - mouseX),dy = Math.abs(axisy.p2c(y) - mouseY);
                    dist = dx * dx + dy * dy; 
                    if (dist < smallestDistance) {
                        smallestDistance = dist;
                        item = [i, j / ps];
                    }
                    break;
                case "vertical":
                    if(between(mouseX,axisx.p2c(x),axisx.p2c(x + serie.nearBy.width))) {
                        dist = Math.abs(axisy.p2c(y) - mouseY);
                        if(dist < serie.nearBy.distance){ item = [i, j / ps];}
                    }
                    break;
                case "horizontal":
                    var axisymin = (axisy.datamin < 0) ? Math.max(0,axisy.datamin) : Math.min(0,axisy.datamin);
                    if(between(mouseY,axisy.p2c(y),axisy.p2c(axisymin))){
                        dist = Math.abs(axisx.p2c(x) - mouseX);
                        if(dist <= serie.nearBy.distance){ item = [i, j / ps];}
                    }
                    break;
                default:
            }
        }
        return item;
    }
    function drawHoverDefault(octx,serie,dataIndex){ }
    function drawEditDefault(octx,x,y,serie){
        var axisx = serie.xaxis,axisy = serie.yaxis;
        if (x < axisx.min || x > axisx.max || y < axisy.min || y > axisy.max){ return;}
        switch(serie.nearBy.findMode){
            case "circle":
                var pointRadius = serie.points.radius + serie.points.lineWidth / 2;
                octx.lineWidth = pointRadius;
                octx.strokeStyle = $.color.parse(serie.color).scale('a', 0.5).toString();
                var radius = 1.5 * pointRadius;
                x = axisx.p2c(x),y = axisy.p2c(y);
                octx.beginPath();
                octx.arc(x, y, radius, 0, 2 * Math.PI, false);    
                octx.fillStyle = "#ff8080";
                octx.fill();
                octx.lineWidth = 2;
                octx.moveTo(x,y-radius);
                octx.lineTo(x,y+radius);
                octx.moveTo(x-radius,y);
                octx.lineTo(x+radius,y);     
                octx.closePath();
                octx.stroke();
                break;
            case "vertical":
                octx.lineWidth = 2;
                octx.strokeStyle = $.color.parse(serie.color).scale('a', 0.5).toString();
                octx.beginPath();
                octx.moveTo(axisx.p2c(x),axisy.p2c(y));
                octx.lineTo(axisx.p2c(x + serie.nearBy.width),axisy.p2c(y));
                octx.closePath();
                octx.stroke();
                break;
            case "horizontal":
                octx.lineWidth = 4;
                octx.strokeStyle = $.color.parse(serie.color).scale('a',0.5).toString();
                octx.beginPath();
                octx.moveTo(axisx.p2c(x),axisy.p2c(y));
                var axisymin = (axisy.datamin < 0) ? Math.max(0,axisy.datamin) : Math.min(0,axisy.datamin);
                octx.lineTo(axisx.p2c(x),axisy.p2c(axisymin));
                octx.closePath();
                octx.stroke();
                break;
        }
    }
    $.plot.plugins.push({
        init: init,
        options: options,    
        name: 'mouse',
        version: '0.2'
    });
    var between = $.plot.JUMlib.library.between;
})(jQuery);
