/*
 * The MIT License

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
    var pluginName = "contour", pluginVersion = "0.1";
    var options ={
        series:{
            contour:{
                active: false,
                show: false,
                ellipseStep: 0.1
            }
        },
        grid:{
            overlay:{image:null,opacity:0.2}
        }
    };
    var replaceOptions = { };
    var defaultOptions = {
        series: {
            editMode: 'xy',
            nearBy: {
                distance: 7,
                findItem: null,
                findMode: "circle",
                drawHover: null
            }
        }
    };	
    function init(plot){
        var offset = null, opt = null, series = null;
        plot.hooks.processOptions.push(processOptions);
        function processOptions(plot,options){
            if(options.series.contour.active){
                $.extend(true,options,replaceOptions);
                $.plot.JUMlib.data.extendEmpty(options,defaultOptions);
                opt = options;
                plot.hooks.processRawData.push(processRawData);
                plot.hooks.drawSeries.push(drawSeries);
                if(opt.grid.overlay.image){ plot.hooks.draw.push(draw);}
            }
        }
        function processRawData(plot,s,data,datapoints){
            if(s.contour.show === true){
                s.nearBy.findItem = findNearbyItemcontour;
                s.nearBy.drawHover = drawHovercontour;
            }
        }
        function drawSeries(plot, ctx, serie){ 
            if(serie.contour.show){
                if(opt.series.contour.debug.active === true) { series = serie;}
                offset = plot.getPlotOffset();
                for (var j = 0; j < serie.data.length; j++){drawcontour(ctx,serie,j,serie.color);}
            }
        }
        function draw(plot,ctx){
            var img = opt.grid.overlay.image;
            var d = '<div style="position:absolute;width:' + plot.width() + ';height:' + plot.height() + ';'
                + 'top:' + offset.top + ';left:' + offset.left + ';">';
            d = $(d);
            $(img).css("opacity",opt.grid.overlay.opacity).width(plot.width()).height(plot.height());
            $(img).css("top",offset.top).css("position","absolute").css("left",offset.left);
            $(img).appendTo(d);
            d.appendTo(plot.getPlaceholder());
        }
        function drawcontour(ctx,serie,j,color){
            var data = serie.data[j];
            var x = parseInt(offset.left + serie.xaxis.p2c(data[0]),0),
                y = parseInt(offset.top + serie.yaxis.p2c(data[1]),0),
                w = parseInt(serie.xaxis.scale * data[2],0),
                h = parseInt(serie.yaxis.scale * data[3],0);
            drawEllipse(ctx,serie,x,y,w,h,data[4],color);
        }
        function drawEllipse(ctx,serie,xC, yC, width, height, rotation,color) {
            var x, y, rW, rH, inc;
            inc = serie.contour.ellipseStep; //value by which we increment the angle in each step
            rW = width / 2; //horizontal radius
            rH = height / 2; //vertical radius
            x = xC + rW * Math.cos(rotation); // ...we will treat this as angle = 0
            y = yC + rW * Math.sin(rotation);
            ctx.save()
            ctx.beginPath();
            ctx.fillStyle = color;
            ctx.moveTo(x, y); //set the starting position
            for (var angle = inc; angle<2*Math.PI; angle+=inc) { //increment the angle from just past zero to full circle (2 Pi radians)
                x = xC + rW * Math.cos(angle) * Math.cos(rotation) - rH * Math.sin(angle) * Math.sin(rotation);
                y = yC + rW * Math.cos(angle) * Math.sin(rotation) + rH * Math.sin(angle) * Math.cos(rotation);
                ctx.lineTo(x, y); //draw a straight line segment. if the increment is small enough, this will be
                //indistinguishable from a curve in an on-screen pixel array
            }
            ctx.closePath();
            ctx.fill(); 
            ctx.restore();
        }

        function findNearbyItemcontour(mouseX, mouseY,i,serie){
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
                if(serie.contour.show){
                    for(var j = 0; j < serie.data.length; j++){
                        var dataitem;
                        dataitem = serie.data[j];
                    }
                }
                return item;
            }
            function findNearbyItem(mouseX,mouseY,i,serie){
                var item = null;
                if(serie.contour.show){
                    for(var j = 0; j < serie.data.length; j++){
                        var dataitem;
                        dataitem = serie.data[j];
                    }
                }
                return item;
            }
        }
        function drawHovercontour(octx,serie,dataIndex){
            octx.save();
            octx.translate(-offset.left,-offset.top);
            var c = "rgba(255,255,255," + serie.bandwidth.highlight.opacity + ")";
            drawcontour(octx,serie,dataIndex,c);
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