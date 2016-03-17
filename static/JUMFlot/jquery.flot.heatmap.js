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
/* this plugin is strongly based on the source in heatmap.js from Patrick Wied
 * Patrick created a great tool, which does much more than this plugin
 * Give him a try and visite his homepage http://www.patrick-wied.at
 * or got directly to http://www.patrick-wied.at/static/heatmapjs/
 */

(function ($){
    //"use strict";
    var pluginName = "heatmap", pluginVersion = "0.3";
    var options ={
        series:{
            heatmap:{
                active: false,
                show: false,
                backImage: null,
                radiusIn : 10,
                radiusOut : 20,
                visible : true,
                width : 0,
                height : 0,
                max : false,
                gradient : { 0.45: "rgb(0,0,255)", 0.55: "rgb(0,255,255)", 0.65: "rgb(0,255,0)", 0.95: "yellow", 1.0: "rgb(255,0,0)"},
                opacity: 180,
                highlight: { opacity: 0.5 }
            }
        }
    };
    var defaultOptions = {
        series:{
            nearBy:{
                distance: 6,
                findItemDefault: null,
                findMode: "circle",
                drawHover: null
            }
        }
    };
    function init(plot){
        var opt = null, offset = "7", acanvas = null, actx = null, series = null;
        plot.hooks.processOptions.push(processOptions);
        function processOptions(plot,options){
            if(options.series.heatmap.active){
                $.plot.JUMlib.data.extendEmpty(options,defaultOptions);               
                opt = options;
                plot.hooks.processRawData.push(processRawData);
                plot.hooks.drawBackground.push(drawBackground);
                plot.hooks.drawSeries.push(drawSeries);
                initColorPalette();
            }
        }
        function initColorPalette(){
            var canvas = document.createElement("canvas");
            canvas.width = "1";
            canvas.height = "256";
            var ctx = canvas.getContext("2d"),
                grad = ctx.createLinearGradient(0,0,1,256),
                gradient = opt.series.heatmap.gradient;
            for(var x in gradient){
                grad.addColorStop(x, gradient[x]);
            }          
            ctx.fillStyle = grad;
            ctx.fillRect(0,0,1,256);
            opt.series.heatmap.gradient = ctx.getImageData(0,0,1,256).data;          
            delete canvas; delete grad; delete ctx;
        }    
        function processRawData(plot,s,data,datapoints){
            if(s.heatmap.show === true){
                s.nearBy.findItemDefault = s.nearBy.findItem;
                s.nearBy.findItem = findNearbyItemHeatmap;
                var img = new Image();
                img.src = opt.series.heatmap.backImage;
            }
        }
        function drawBackground(plot,ctx){            
            var img;
            if(opt.series.heatmap.backImage){
                img = opt.series.heatmap.backImage;
                offset = plot.getPlotOffset();
                ctx.save();
                ctx.translate(offset.left,offset.top);
                ctx.drawImage(img,0,0,plot.width(),plot.height());
                ctx.restore();
            }
        }
        function drawSeries(plot, ctx, serie){
            //var acanvas,actx;
            if(opt.series.heatmap.debug.active === true) { series = serie;}
            acanvas = document.createElement('canvas');
            acanvas.style.top = "0px";
            acanvas.style.left = "0px";
            acanvas.style.position = "absolute";
            acanvas.height = ctx.canvas.height;
            acanvas.width = ctx.canvas.width;
            actx = acanvas.getContext("2d");
            offset = plot.getPlotOffset();     
            for(var i = serie.data.length - 1; i >= 0 ;i--){
                var pt = serie.data[i]; 
                drawAlpha(ctx,actx,serie.xaxis.p2c(pt[0]),serie.yaxis.p2c(pt[1]),pt[2]);  
            }
            function drawAlpha(ctx,actx,x, y, count){     
                // storing the variables because they will be often used
                var r1 = serie.heatmap.radiusIn,
                    r2 = serie.heatmap.radiusOut,
                    lctx = actx,
                    max = serie.heatmap.max,
                    // create a radial gradient with the defined parameters. we want to draw an alphamap
                    rgr = lctx.createRadialGradient(x,y,r1,x,y,r2),
                    xb = x-r2, yb = y-r2, mul = 2*r2;
                // the center of the radial gradient has .1 alpha value
                rgr.addColorStop(0, 'rgba(0,0,0,'+((count)?(count/serie.heatmap.max):'0.1')+')');  
                // and it fades out to 0
                rgr.addColorStop(1, 'rgba(0,0,0,0)');
                // drawing the gradient
                lctx.fillStyle = rgr; 
                lctx.fillRect(xb,yb,mul,mul);
                // finally colorize the area    
                colorize(ctx,actx,xb,yb,offset);     
            }
            function colorize(ctx,actx,x, y,offset){
                // get the private variables
                var width = plot.width(),
                    radiusOut = serie.heatmap.radiusOut,
                    height = plot.heigth;
                var x2 = radiusOut*2;                
                if(x+x2>width){ x=width-x2;}
                if(x<0){ x=0;}
                if(y<0){ y=0;}
                if(y+x2>height){ y=height-x2;}         
                var image = actx.getImageData(x,y,x2,x2),  // get the image data
                    imageData = image.data,  // some performance tweaks
                    length = imageData.length,
                    xp = x + offset.left,
                    yp = y + offset.top;
                var orgImage = ctx.getImageData(xp,yp,x2,x2),
                    orgImageData = orgImage.data,
                    palette = opt.series.heatmap.gradient,
                    opacity = opt.series.heatmap.opacity;
                // loop thru the area
                for(var i=3; i < length; i+=4){
                    // [0] -> r, [1] -> g, [2] -> b, [3] -> alpha
                    var alpha = imageData[i];
                    offset = alpha*4;
                    if(!offset){ continue;}    
                    // we ve started with i=3
                    // set the new r, g and b values
                    orgImageData[i-3]=palette[offset];
                    orgImageData[i-2]=palette[offset+1];
                    orgImageData[i-1]=palette[offset+2];
                    // we want the heatmap to have a gradient from transparent to the colors
                    // as long as alpha is lower than the defined opacity (maximum), we'll use the alpha value
                    orgImageData[i] = (alpha < opacity)?alpha:opacity;
                }
                // the rgb data manipulation didn't affect the ImageData object(defined on the top)
                // after the manipulation process we have to set the manipulated data to the ImageData object
                orgImage.data = orgImageData;
                ctx.putImageData(orgImage,xp,yp);
            }
        }
        function findNearbyItemHeatmap(mouseX, mouseY,i,serie){
            var item = null;
            item = serie.nearBy.findItemDefault(mouseX,mouseY,i,serie);
            return item;
        }
    }
    $.plot.plugins.push({
        init: init,
        options: options,
        name: pluginName,
        version: pluginVersion
    });
})(jQuery); 