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
    var pluginName = "background", pluginVersion = "0.4";
    var options ={
        grid:{
            background:{
                active: false,
                mode:"color",       //image,color,userdefined
                color:{colors:["white","yellow","orange","blue"] },
                image:null,
                fncDraw:null,
                setZIndex: false
            },
            overlay:{
                active:false,
                image:null,
                opacity:0.2
            }
        }
    };
    function init(plot,classes){
        var Canvas,background,bctx,opt,offset;
        var acanvas,actx,animateFunc,lctx;
        Canvas = classes.Canvas;
        plot.hooks.processOptions.push(processOptions);
        function processOptions(plot,options){
            if(options.grid.background.active === true){
                opt = options;
                plot.hooks.drawBackground.push(drawBackground);
                if(options.grid.overlay.active === true) plot.hooks.draw.push(draw);
            }
        }
        function drawBackground(plot,ctx){
            opt = plot.getOptions();
            lctx = ctx;
            var zIndex = opt.grid.background.setZIndex;
            background = new Canvas("flot-background", plot.getPlaceholder());
            if($.isNumeric(zIndex) === true){
                    $(plot.getPlaceholder().children(".flot-overlay")).css('z-index',zIndex + 1);
                    $(plot.getCanvas()).css('z-index',zIndex);
                    $(background.element).css('z-index',zIndex - 1);                                
            }
            else{
                if(opt.grid.background.setZIndex === true){
                    $(plot.getPlaceholder().children(".flot-overlay")).css('z-index',2);
                    $(plot.getCanvas()).css('z-index',1);
                    $(background.element).css('z-index',0);                
                }
                else{ $(background.element).css('z-index',-1); }
            }
            bctx = background.context;
            offset = plot.getPlotOffset();
            bctx.save();
            bctx.translate(offset.left,offset.top);
            switch(opt.grid.background.mode){
                case "image":
                    drawImage(plot,bctx);
                    break;
                case "color":
                    drawColor(plot,bctx);
                    break;
                case "userdefined":
                    drawByFunction(plot,bctx);
                    break;
                default:
                    drawColor(plot,bctx);
            }
            bctx.restore();
        }
        function drawByFunction(plot,bctx){
            opt.grid.background.fncDraw(plot,bctx,plot.width(),plot.height());
        }
        function drawImage(plot,bctx){
            var image = opt.grid.background.image;        
            if(typeof image !== "undefined"){
                bctx.drawImage(image,0,0,plot.width(),plot.height());
            } 
        }
        function drawColor(plot,bctx){
            var color = $.plot.JUMlib.data.getColor({
                ctx:bctx,color:opt.grid.background.color,
                left:0,top:0,height:plot.height(),width:plot.width()
            });
            bctx.fillStyle = color;
            bctx.fillRect(0,0,plot.width(),plot.height());
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
     }
    var getColor = $.plot.JUMlib.data.getColor;
    $.plot.plugins.push({
        init: init,
        options: options,
        name: pluginName,
        version: pluginVersion
    });
})(jQuery); 