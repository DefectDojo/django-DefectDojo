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
    var pluginName = "video", pluginVersion = "0.2";
    var options ={
        series: {
            video:{
                active: false,
                show: false,
                stepAction: "simple",
                stepCollection:{
                    simple: { runStep: simpleStep, walkPad: "#stepPad", walkTime:2000 },
                    youtube: { runStep: youtubeStep, videoPad: "#videoPad", width: 400, height: 300, maxDuration: 20000, noVideoDuration:2000 },
                    delay: { runStep: delayStep, duration: 1000},
                    byStep: { stepDataIndex:2}                   
                }
            }
        }
    };
    var replaceOptions = { grid:{ show: false} };
    var defaultOptions = { };
    function simpleStep(stepData,actionData){
        var dfd,t;
        if(actionData.walkPad) {
           dfd = $.Deferred();
           $(actionData.walkPad).append("<br>" + stepData.data[2]);
           t = window.setTimeout(function(){ dfd.resolve();},actionData.walkTime );
           return dfd.promise(); 
        }
        else { alert(stepData.data[2]);}
    }
    function youtubeStep(stepData,actionData){
        var dfd,t;
        if(actionData.videoPad){
            dfd = $.Deferred();
            if(stepData.data.length>3){
                if(typeof stepData.data[3] === "string"){
                    jQuery.tubeplayer.defaults.afterReady = function(){
                        jQuery(actionData.videoPad).tubeplayer("play");
                    };                    
                    jQuery(actionData.videoPad).tubeplayer({
                        width: actionData.width,height: actionData.height,
                        initialVideo: stepData.data[3], 
                        onPlayerEnded: finishPlayer,onStop: finishPlayer
                    });
                    jQuery(actionData.videoPad).tubeplayer("play");
                    t = window.setTimeout(function(){ finishPlayer(); }, actionData.maxDuration); 
                }                
            }
            else { t = window.setTimeout(function(){ dfd.resolve(); }, actionData.noVideoDuration)}
            
            return dfd.promise();
        }
        else{ alert("no videoPad defined"); }
        function finishPlayer(){
            jQuery(actionData.videoPad).tubeplayer("destroy");
            dfd.resolve(); 
        }
    }	
    function delayStep(stepData,actionData){
        var dfd,t;
        dfd = $Deferred();
        t = window.setTimeout(function(){ dfd.resolve();},actionData.duration);
        return dfd.promise();
    }
    function init(plot, classes){ 
        var data = null, opt = null, plt = null, series = null;
        var done = false, actualStep = 0, maxSteps = 0, defs = [];
        plot.hooks.processOptions.push(processOptions);
        function processOptions(plot,options){
            if(options.series.video.active){
                opt = options;
                $.extend(true,options,replaceOptions);
                $.plot.JUMlib.data.extendEmpty(options,defaultOptions);
                opt = options;
                plot.hooks.draw.push(draw);
                plot.hooks.bindEvents.push(bindEvents);
            }
        }
        function draw(plot,ctx){
            var i,j;
            if(opt.series.video.active === true){
                if(done === false){
                    data = plot.getData();
                    for(i = 0; i < data.length; i++){
                        if(data[i].video.show === true){
                            series = data[i].data;
                            maxSteps = Math.max(maxSteps,data[i].data.length)
                            data[i].dataOrg = clone(data[i].data);
                            for(j = 0; j < data[i].data.length; j++){ data[i].data[j] = null; }
                        }
                    } 
                    plot.setData(data);
                    done = true;              
                }
            }
        }
        function bindEvents(plot,eventHolder){
            if (opt.series.video.active === true){
                plt = plot; 
                window.setTimeout(videoLoop,0);
            }
        }
        function videoLoop(){
            var i,defs = [],r,v, dt;
            for(var i = 0; i < data.length; i++){ 
                if(data[i].video.show === true){
                    data[i].data[actualStep] = data[i].dataOrg[actualStep];
                    plt.setData(data);
                    plt.draw();
                    v = data[i].video;
                    if(v.stepAction === "byStep"){ callAction(v.data[i].data[i][v.stepCollection.byStep.stepDataIndex]); }
                    else { callAction(v.stepAction); }
                }
            }
            actualStep++;
            if(actualStep < maxSteps){ $.when.apply(null,defs).then(function(){videoLoop();}); }
            function callAction(v){       
                r = { seriesIndex:i, dataIndex:actualStep, data:data[i].data[actualStep], serie: data[i]};
                if(typeof v.stepAction === "string"){
                    defs.push(v.stepCollection[v.stepAction].runStep(r,v.stepCollection[v.stepAction])); }
                else if(typeof v.stepAction === "object"){defs.push(v.stepAction.runStep(r,v.stepAction)); }
            }
        }
        function clone(obj){
            if(obj === null || typeof(obj) !== 'object'){ return obj;}
            var temp = new obj.constructor();
            for(var key in obj){temp[key] = clone(obj[key]); }
            return temp;
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