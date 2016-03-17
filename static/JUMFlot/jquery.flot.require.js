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
(function($) {
    function required(){
        "use strict";
        var requires,opt,dta,gCallback,log = "",missingPlugins = [],checkOnly = false;
        requires = [
            {"baseAdress":"http://www.flotcharts.org/flot/"},
            {"url":"jquery.flot.js","loaded":false,"check":{"mode":"always"}},
            {"url":"jquery.flot.time.js","loaded":false,"check":{"object":"xaxis.mode","mode":"equal","value":"time"}},
            {"url":"jquery.flot.time.js","loaded":false,"check":{"object":"yaxis.mode","mode":"equal","value":"time"}},
            {"url":"jquery.flot.categories.js","loaded":false,"check":{"object":"xaxis.mode","mode":"equal","value":"categories"}},
            {"url":"jquery.flot.categories.js","loaded":false,"check":{"object":"yaxis.mode","mode":"equal","value":"categories"}},
            {"url":"jquery.flot.selection.js","loaded":false,"check":{"object":"selection","mode":"exists"}},
            {"url":"jquery.flot.navigate.js","loaded":false,"check":{"object":"zoom","mode":"exists"}},
            {"url":"jquery.flot.navigate.js","loaded":false,"check":{"object":"pan","mode":"exists"}},
            {"url":"jquery.flot.threshold.js","loaded":false,"check":{"object":"threshold","mode":"exists"}},
            {"url":"jquery.flot.stack.js","loaded":false,"check":{"object":"series.stack","mode":"exists"}},
            {"url":"jquery.flot.crosshair.js","loaded":false,"check":{"object":"crosshair","mode":"exists"}},
            {"url":"jquery.flot.image.js","loaded":false,"check":{"object":"series.image","mode":"exists"}},
            {"url":"jquery.flot.pie.js","loaded":false,"check":{"object":"series.pie","mode":"exists"}},
            {"url":"jquery.flot.canvas.js","loaded":false,"check":{"object":"canvas","mode":"exists"}},
            {"url":"jquery.flot.symbol.js","loaded":false,"check":{"object":"points.symbol","mode":"data"}},
            {"url":"jquery.flot.threshold.js","loaded":false,"check":{"object":"threshold","mode":"data"}},
            {"url":"jquery.flot.fillbetween.js","loaded":false,"check":{"object":"fillBetween","mode":"data"}},
            {"baseAdress":"../../Experimental/"},
            {"url":"jquery.flot.JUMlib.js","loaded":false,"check":{"object":"grid.editable","mode":"equal","value":true}},
            {"url":"jquery.flot.JUMlib.js","loaded":false,"check":{"object":"series.bandwidth","mode":"exists"}},
            {"url":"jquery.flot.JUMlib.js","loaded":false,"check":{"object":"series.bubbles","mode":"exists"}},
            {"url":"jquery.flot.JUMlib.js","loaded":false,"check":{"object":"series.candlestick","mode":"exists"}},
            {"url":"jquery.flot.JUMlib.js","loaded":false,"check":{"object":"series.gantt","mode":"exists"}},
            {"url":"jquery.flot.JUMlib.js","loaded":false,"check":{"object":"series.heatmap","mode":"exists"}},
            {"url":"jquery.flot.JUMlib.js","loaded":false,"check":{"object":"series.pyramid","mode":"exists"}},
            {"url":"jquery.flot.JUMlib.js","loaded":false,"check":{"object":"series.rectangle","mode":"exists"}},
            {"url":"jquery.flot.JUMlib.js","loaded":false,"check":{"object":"series.spider","mode":"exists"}},
            {"url":"jquery.flot.JUMlib.js","loaded":false,"check":{"object":"series.grow","mode":"exists"}},
            {"url":"jquery.flot.JUMlib.js","loaded":false,"check":{"object":"series.radar","mode":"exists"}},
            {"url":"jquery.flot.JUMlib.js","loaded":false,"check":{"object":"series.spiral","mode":"exists"}},
            {"url":"jquery.flot.JUMlib.js","loaded":false,"check":{"object":"series.rose","mode":"exists"}},
            {"url":"jquery.flot.mouse.js","loaded":false,"check":{"object":"grid.editable","mode":"equal","value":true}},
            {"url":"jquery.flot.mouse.js","loaded":false,"check":{"object":"series.bandwidth","mode":"exists"}},
            {"url":"jquery.flot.mouse.js","loaded":false,"check":{"object":"series.bubbles","mode":"exists"}},
            {"url":"jquery.flot.mouse.js","loaded":false,"check":{"object":"series.candlestick","mode":"exists"}},
            {"url":"jquery.flot.mouse.js","loaded":false,"check":{"object":"series.gantt","mode":"exists"}},
            {"url":"jquery.flot.mouse.js","loaded":false,"check":{"object":"series.heatmap","mode":"exists"}},
            {"url":"jquery.flot.mouse.js","loaded":false,"check":{"object":"series.pyramid","mode":"exists"}},
            {"url":"jquery.flot.mouse.js","loaded":false,"check":{"object":"series.rectangle","mode":"exists"}},
            {"url":"jquery.flot.mouse.js","loaded":false,"check":{"object":"series.spider","mode":"exists"}},
            {"url":"jquery.flot.mouse.js","loaded":false,"check":{"object":"series.radar","mode":"exists"}},
            {"url":"jquery.flot.mouse.js","loaded":false,"check":{"object":"series.spiral","mode":"exists"}},
            {"url":"jquery.flot.mouse.js","loaded":false,"check":{"object":"series.rose","mode":"exists"}},
            {"url":"jquery.flot.bandwidth.js","loaded":false,"check":{"object":"series.bandwidth","mode":"exists"}},
            {"url":"jquery.flot.bubbles.js","loaded":false,"check":{"object":"series.bubbles","mode":"exists"}},
            {"url":"jquery.flot.candlestick.js","loaded":false,"check":{"object":"series.candlestick","mode":"exists"}},
            {"url":"jquery.flot.gantt.js","loaded":false,"check":{"object":"series.gantt","mode":"exists"}},
            {"url":"jquery.flot.heatmap.js","loaded":false,"check":{"object":"series.heatmap","mode":"exists"}},
            {"url":"jquery.flot.pyramid.js","loaded":false,"check":{"object":"series.pyramid","mode":"exists"}},
            {"url":"jquery.flot.rectangle.js","loaded":false,"check":{"object":"series.rectangle","mode":"exists"}},
            {"url":"jquery.flot.spider.js","loaded":false,"check":{"object":"series.spider","mode":"exists"}},
            {"url":"jquery.flot.radar.js","loaded":false,"check":{"object":"series.radar","mode":"exists"}},
            {"url":"jquery.flot.spiral.js","loaded":false,"check":{"object":"series.spiral","mode":"exists"}},
            {"url":"jquery.flot.rose.js","loaded":false,"check":{"object":"series.rose","mode":"exists"}},
            {"url":"jquery.flot.background.js","loaded":false,"check":{"object":"grid.background","mode":"exists"}}
        ];
        this.getRequires = function(){ return requires; }
        this.getMissingPlugins = function(mode){ 
            if(mode){
                if(mode === "object"){ return missingPlugins; }
                else{
                    var i,r = "Missed plugins\n\n";
                    for(var i = 0; i < missingPlugins.length; i++){ r += missingPlugins[i][1] + "\n"; }
                    return r;
                }
            }
            else{ return missingPlugins;}
        }
        this.log = function(){ return log; }
        this.loadRequired = function(url){
            jQuery.ajax({
                url: url,dataType:"json",async:false,
                success: function(data) {requires = data; },
                error: function(e){alert("requires could not be loaded from " + url); }
            });            
        }
        this.addRequired = function(newRequired){ requires.push(newRequired); }
        this.loadScripts = function(options,callback,data){
            opt = options;
            gCallback = callback;
            dta = data;
            checkAlways();
        }
        this.loadScriptsDeferred = loadScriptsDeferred;
        function checkAlways(){
            var i,baseAdress,toLoad = [];
            for(i = 0; i < requires.length; i++){
                if(requires[i].baseAdress) { baseAdress = requires[i].baseAdress;}
                else{
                    if(requires[i].loaded === false){
                        if(requires[i].check.mode === "always"){
                            toLoad.push([baseAdress,requires[i].url]);
                            setLoaded(requires[i]);
                        }
                    }
                }
            }
            if(toLoad.length > 0){ loadScriptsDeferred(toLoad,"checkSingle");} else{checkSingle();}
        }
        function checkSingle(){
            var i,baseAdress,toLoad = [];
            for(var i = 0; i < requires.length; i++){
                if(requires[i].baseAdress) { baseAdress = requires[i].baseAdress;}
                else{if(requires[i].loaded === false){checkForLoad(requires[i]);} }
            }
            if(toLoad.length > 0){ loadScriptsDeferred(toLoad,"checkData"); } else{ checkData(); }
            function checkForLoad(require){
                var objs,cmd,i,obj,z;
                if(require.check.mode === "exists" || require.check.mode === "equal"){
                    objs = require.check.object.split('.');
                    obj = opt;
                    for(i = 0; i < objs.length;i++){
                        obj = obj[objs[i]];
                        if(typeof obj === 'undefined'){ return false; }
                    }
                    if(require.check.mode === "equal"){
                        if(obj === require.check.value){
                            toLoad.push([baseAdress,require.url]);
                            setLoaded(require);
                            return true;                               
                        }
                        else{ return false; }
                    }
                    else{
                        toLoad.push([baseAdress,require.url]);
                        setLoaded(require);
                        return true;
                    }
                }
            }
        }
        function checkData(){
            var i,baseAdress,toLoad = [];
            for(var i = 0; i < requires.length; i++){
                if(requires[i].baseAdress) { baseAdress = requires[i].baseAdress;}
                else{if(requires[i].loaded === false){checkForData(requires[i]);} }
            }
            if(toLoad.length > 0){ loadScriptsDeferred(toLoad,"gCallback"); } else{gCallback();}
            function checkForData(require){
                var i,t;
                if(dta){
                    if(dta.length){
                        for(var i = 0; i < dta.length; i++){
                            t = getObject(require,dta[i]);
                            if(t !== false){
                                toLoad.push([baseAdress,require.url]);
                                setLoaded(require);
                                return true;
                            }
                        }
                    }
                    else{ 
                        t = getObject(require,dta);
                        if(t !== false){
                            toLoad.push([baseAdress,require.url]);
                            setLoaded(require);
                            return true;
                        }
                    }
                }
                return false;
            }
            function getObject(require,data){
                var objs = [],i,obj;
                objs = require.check.object.split('.');
                obj = data;
                for(i = 0; i < objs.length;i++){
                    obj = obj[objs[i]];
                    if(typeof obj === 'undefined'){ return false; }
                }
                return obj;
            }
        }
        function loadScriptsDeferred(toLoad,callback){
            var i,j,cmd,script;
            if(checkOnly === true){eval(callback + "()");}
            else{
                cmd = "$.when(";
                j = 0;
                for(i = 0; i < toLoad.length; i++){
                    if(scriptLoaded(toLoad[i]) === false){
                        if(j > 0){ cmd += ","; }
                        cmd += "loadScriptDeferred('" + toLoad[i][0] + toLoad[i][1] + "')";
                        missingPlugins.push(toLoad[i]);
                        j++;
                    }
                }
                cmd +=").then(function(){" + callback + "();})"; 
                if(j > 0 ){ eval(cmd); }else { eval(callback + "()"); }
            }
        }
        function scriptLoaded(url){
            var i,scripts = [];
            scripts = $("script");
            if(scripts.length > 0){
                for(i = 0;i < scripts.length;i++){
                    if(scripts[i].src == (url[0] + url[1])){ return true; }
                }
            }
            return false;
        }
        function loadScriptDeferred(url){
            var dfd = $.Deferred();
            jQuery.ajax({
                url: url,dataType:"script",
                success: function(data) {log += url + " loaded\n";dfd.resolve(); },
                error: function(e){log += "error loading " + url + "\n"; console.log(e);dfd.resolve(); }
            });            
            return dfd.promise();
        }
        function setLoaded(require){
            var i;
            for(i = 0; i < requires.length; i++){
                if(require.url == requires[i].url){ requires[i].loaded = true;}
            }
        }
    }
    $.flot_requires = function(options,callback,data,requiresUrl,checkonly){ 
        var r = new required();
        dta = data;
        if(requiresUrl){ r.loadRequired(requiresUrl); }
        if(checkonly) { checkOnly = checkonly; }
        if(callback){ r.loadScripts(options,callback,data); }
        return r;
    };
})(jQuery);
