(function(e){function t(t){for(var a,r,o=t[0],i=t[1],l=t[2],u=0,d=[];u<o.length;u++)r=o[u],Object.prototype.hasOwnProperty.call(n,r)&&n[r]&&d.push(n[r][0]),n[r]=0;for(a in i)Object.prototype.hasOwnProperty.call(i,a)&&(e[a]=i[a]);b&&b(t);while(d.length)d.shift()();return c.push.apply(c,l||[]),s()}function s(){for(var e,t=0;t<c.length;t++){for(var s=c[t],a=!0,r=1;r<s.length;r++){var o=s[r];0!==n[o]&&(a=!1)}a&&(c.splice(t--,1),e=i(i.s=s[0]))}return e}var a={},r={app:0},n={app:0},c=[];function o(e){return i.p+"js/"+({}[e]||e)+"."+{"chunk-1f0cc288":"3af6e177","chunk-4b00ff04":"12f9860a","chunk-cf2bffa6":"fa5cf2b9"}[e]+".js"}function i(t){if(a[t])return a[t].exports;var s=a[t]={i:t,l:!1,exports:{}};return e[t].call(s.exports,s,s.exports,i),s.l=!0,s.exports}i.e=function(e){var t=[],s={"chunk-1f0cc288":1,"chunk-4b00ff04":1,"chunk-cf2bffa6":1};r[e]?t.push(r[e]):0!==r[e]&&s[e]&&t.push(r[e]=new Promise((function(t,s){for(var a="css/"+({}[e]||e)+"."+{"chunk-1f0cc288":"ec74a5d5","chunk-4b00ff04":"4d251861","chunk-cf2bffa6":"8347fbac"}[e]+".css",n=i.p+a,c=document.getElementsByTagName("link"),o=0;o<c.length;o++){var l=c[o],u=l.getAttribute("data-href")||l.getAttribute("href");if("stylesheet"===l.rel&&(u===a||u===n))return t()}var d=document.getElementsByTagName("style");for(o=0;o<d.length;o++){l=d[o],u=l.getAttribute("data-href");if(u===a||u===n)return t()}var b=document.createElement("link");b.rel="stylesheet",b.type="text/css",b.onload=t,b.onerror=function(t){var a=t&&t.target&&t.target.src||n,c=new Error("Loading CSS chunk "+e+" failed.\n("+a+")");c.code="CSS_CHUNK_LOAD_FAILED",c.request=a,delete r[e],b.parentNode.removeChild(b),s(c)},b.href=n;var m=document.getElementsByTagName("head")[0];m.appendChild(b)})).then((function(){r[e]=0})));var a=n[e];if(0!==a)if(a)t.push(a[2]);else{var c=new Promise((function(t,s){a=n[e]=[t,s]}));t.push(a[2]=c);var l,u=document.createElement("script");u.charset="utf-8",u.timeout=120,i.nc&&u.setAttribute("nonce",i.nc),u.src=o(e);var d=new Error;l=function(t){u.onerror=u.onload=null,clearTimeout(b);var s=n[e];if(0!==s){if(s){var a=t&&("load"===t.type?"missing":t.type),r=t&&t.target&&t.target.src;d.message="Loading chunk "+e+" failed.\n("+a+": "+r+")",d.name="ChunkLoadError",d.type=a,d.request=r,s[1](d)}n[e]=void 0}};var b=setTimeout((function(){l({type:"timeout",target:u})}),12e4);u.onerror=u.onload=l,document.head.appendChild(u)}return Promise.all(t)},i.m=e,i.c=a,i.d=function(e,t,s){i.o(e,t)||Object.defineProperty(e,t,{enumerable:!0,get:s})},i.r=function(e){"undefined"!==typeof Symbol&&Symbol.toStringTag&&Object.defineProperty(e,Symbol.toStringTag,{value:"Module"}),Object.defineProperty(e,"__esModule",{value:!0})},i.t=function(e,t){if(1&t&&(e=i(e)),8&t)return e;if(4&t&&"object"===typeof e&&e&&e.__esModule)return e;var s=Object.create(null);if(i.r(s),Object.defineProperty(s,"default",{enumerable:!0,value:e}),2&t&&"string"!=typeof e)for(var a in e)i.d(s,a,function(t){return e[t]}.bind(null,a));return s},i.n=function(e){var t=e&&e.__esModule?function(){return e["default"]}:function(){return e};return i.d(t,"a",t),t},i.o=function(e,t){return Object.prototype.hasOwnProperty.call(e,t)},i.p="",i.oe=function(e){throw console.error(e),e};var l=window["webpackJsonp"]=window["webpackJsonp"]||[],u=l.push.bind(l);l.push=t,l=l.slice();for(var d=0;d<l.length;d++)t(l[d]);var b=u;c.push([0,"chunk-vendors"]),s()})({0:function(e,t,s){e.exports=s("56d7")},2790:function(e,t,s){},"56d7":function(e,t,s){"use strict";s.r(t);var a=s("7a23");const r={id:"app"},n={class:"navbar navbar-expand navbar-dark bg-dark"},c={class:"navbar-nav mr-auto"},o={class:"nav-item"},i={key:0,class:"nav-item"},l={class:"nav-item"},u={key:0,class:"navbar-nav ml-auto"},d={class:"nav-item"},b={class:"nav-item"},m={key:1,class:"navbar-nav ml-auto"},g={class:"nav-item"},f={class:"nav-item"},p={class:"container"};function O(e,t,s,O,h,j){const v=Object(a["E"])("font-awesome-icon"),k=Object(a["E"])("router-link"),y=Object(a["E"])("DigitalClockVue"),w=Object(a["E"])("router-view");return Object(a["x"])(),Object(a["f"])("div",r,[Object(a["g"])("nav",n,[Object(a["g"])("div",c,[Object(a["g"])("li",o,[Object(a["i"])(k,{to:"/home",class:"nav-link"},{default:Object(a["P"])(()=>[Object(a["i"])(v,{icon:"home"}),Object(a["h"])(" Home ")]),_:1})]),j.showAdminBoard?(Object(a["x"])(),Object(a["f"])("li",i,[Object(a["i"])(k,{to:"/admin",class:"nav-link"},{default:Object(a["P"])(()=>[Object(a["h"])("Admin panel")]),_:1})])):Object(a["e"])("",!0),Object(a["g"])("li",l,[j.currentUser?(Object(a["x"])(),Object(a["d"])(k,{key:0,to:"/user",class:"nav-link"},{default:Object(a["P"])(()=>[Object(a["h"])("User")]),_:1})):Object(a["e"])("",!0)]),Object(a["g"])("li",null,[Object(a["i"])(y)])]),j.currentUser?Object(a["e"])("",!0):(Object(a["x"])(),Object(a["f"])("div",u,[Object(a["g"])("li",d,[Object(a["i"])(k,{to:"/register",class:"nav-link"},{default:Object(a["P"])(()=>[Object(a["i"])(v,{icon:"user-plus"}),Object(a["h"])(" Sign Up ")]),_:1})]),Object(a["g"])("li",b,[Object(a["i"])(k,{to:"/login",class:"nav-link"},{default:Object(a["P"])(()=>[Object(a["i"])(v,{icon:"sign-in-alt"}),Object(a["h"])(" Login ")]),_:1})])])),j.currentUser?(Object(a["x"])(),Object(a["f"])("div",m,[Object(a["g"])("li",g,[Object(a["i"])(k,{to:"/profile",class:"nav-link"},{default:Object(a["P"])(()=>[Object(a["i"])(v,{icon:"user"}),Object(a["h"])(" "+Object(a["H"])(j.currentUser.username),1)]),_:1})]),Object(a["g"])("li",f,[Object(a["g"])("a",{class:"nav-link",onClick:t[0]||(t[0]=Object(a["R"])((...e)=>j.logOut&&j.logOut(...e),["prevent"]))},[Object(a["i"])(v,{icon:"sign-out-alt"}),Object(a["h"])(" LogOut ")])])])):Object(a["e"])("",!0)]),Object(a["g"])("div",p,[Object(a["i"])(w)])])}s("14d9");const h=e=>(Object(a["A"])("data-v-4d783a26"),e=e(),Object(a["y"])(),e),j={class:"container"},v={class:"LCD"},k={class:"hours"},y=h(()=>Object(a["g"])("div",{class:"divider"},":",-1)),w={class:"minutes"},x=h(()=>Object(a["g"])("div",{class:"divider"},":",-1)),S={class:"seconds"};function E(e,t,s,r,n,c){return Object(a["x"])(),Object(a["f"])("div",j,[Object(a["g"])("div",v,[Object(a["g"])("div",k,Object(a["H"])(n.hours),1),y,Object(a["g"])("div",w,Object(a["H"])(n.minutes),1),x,Object(a["g"])("div",S,Object(a["H"])(n.seconds),1)])])}var P={name:"DigitalClock",data(){return{hours:0,minutes:0,seconds:0}},mounted(){setInterval(()=>this.setTime(),1e3)},methods:{setTime(){const e=new Date;let t=e.getHours(),s=e.getMinutes(),a=e.getSeconds();t=t<=9?(""+t).padStart(2,0):t,s=s<=9?(""+s).padStart(2,0):s,a=a<=9?(""+a).padStart(2,0):a,this.hours=t,this.minutes=s,this.seconds=a}}},_=(s("afad"),s("6b0d")),I=s.n(_);const L=I()(P,[["render",E],["__scopeId","data-v-4d783a26"]]);var U=L,M={components:{DigitalClockVue:U},computed:{currentUser(){return this.$store.state.auth.user},showAdminBoard(){return!(!this.currentUser||!this.currentUser["roles"])&&this.currentUser["roles"].includes("ROLE_ADMIN")}},methods:{logOut(){this.$store.dispatch("auth/logout"),this.$router.push("/login")}}};s("b59b");const A=I()(M,[["render",O]]);var F=A,q=s("6605");const C={class:"jumbotron d-flex justify-content-center align-items-center centered"};function H(e,t,s,r,n,c){return Object(a["x"])(),Object(a["f"])("div",C," Golikov Andrei. Lab 4. P32092. 7654 ")}var T={name:"Home"};s("8538");const $=I()(T,[["render",H]]);var D=$;const N=e=>(Object(a["A"])("data-v-2e66dac2"),e=e(),Object(a["y"])(),e),B={class:"col-md-12"},R={class:"card card-container"},J=N(()=>Object(a["g"])("img",{id:"profile-img",src:"//ssl.gstatic.com/accounts/ui/avatar_2x.png",class:"profile-img-card"},null,-1)),Q={class:"form-group"},V=N(()=>Object(a["g"])("label",{for:"username"},"Username",-1)),G={class:"form-group"},K=N(()=>Object(a["g"])("label",{for:"password"},"Password",-1)),z={class:"form-group"},W=["disabled"],X={class:"spinner-border spinner-border-sm"},Y=N(()=>Object(a["g"])("span",null,"Login",-1)),Z={class:"form-group"},ee={key:0,class:"alert alert-danger",role:"alert"};function te(e,t,s,r,n,c){const o=Object(a["E"])("Field"),i=Object(a["E"])("ErrorMessage"),l=Object(a["E"])("Form");return Object(a["x"])(),Object(a["f"])("div",B,[Object(a["g"])("div",R,[J,Object(a["i"])(l,{onSubmit:c.handleLogin,"validation-schema":n.schema},{default:Object(a["P"])(()=>[Object(a["g"])("div",Q,[V,Object(a["i"])(o,{name:"username",type:"text",class:"form-control"}),Object(a["i"])(i,{name:"username",class:"error-feedback"})]),Object(a["g"])("div",G,[K,Object(a["i"])(o,{name:"password",type:"password",class:"form-control"}),Object(a["i"])(i,{name:"password",class:"error-feedback"})]),Object(a["g"])("div",z,[Object(a["g"])("button",{class:"btn btn-primary btn-block",disabled:n.loading},[Object(a["Q"])(Object(a["g"])("span",X,null,512),[[a["L"],n.loading]]),Y],8,W)]),Object(a["g"])("div",Z,[n.message?(Object(a["x"])(),Object(a["f"])("div",ee,Object(a["H"])(n.message),1)):Object(a["e"])("",!0)])]),_:1},8,["onSubmit","validation-schema"])])])}var se=s("7bb1"),ae=s("506a"),re={name:"Login",components:{Form:se["c"],Field:se["b"],ErrorMessage:se["a"]},data(){const e=ae["a"]().shape({username:ae["b"]().required("Username is required!"),password:ae["b"]().required("Password is required!")});return{loading:!1,message:"",schema:e}},computed:{loggedIn(){return this.$store.state.auth.status.loggedIn}},created(){this.loggedIn&&this.$router.push("/profile")},methods:{handleLogin(e){this.loading=!0,this.$store.dispatch("auth/login",e).then(()=>{this.$router.push("/profile")},e=>{this.loading=!1,this.message=e.response&&e.response.data&&e.response.data.message||e.message||e.toString()})}}};s("d19a");const ne=I()(re,[["render",te],["__scopeId","data-v-2e66dac2"]]);var ce=ne;const oe=e=>(Object(a["A"])("data-v-43ad05e7"),e=e(),Object(a["y"])(),e),ie={class:"col-md-12"},le={class:"card card-container"},ue=oe(()=>Object(a["g"])("img",{id:"profile-img",src:"//ssl.gstatic.com/accounts/ui/avatar_2x.png",class:"profile-img-card"},null,-1)),de={key:0},be={class:"form-group"},me=oe(()=>Object(a["g"])("label",{for:"username"},"Username",-1)),ge={class:"form-group"},fe=oe(()=>Object(a["g"])("label",{for:"email"},"Email",-1)),pe={class:"form-group"},Oe=oe(()=>Object(a["g"])("label",{for:"password"},"Password",-1)),he={class:"form-group"},je=["disabled"],ve={class:"spinner-border spinner-border-sm"};function ke(e,t,s,r,n,c){const o=Object(a["E"])("Field"),i=Object(a["E"])("ErrorMessage"),l=Object(a["E"])("Form");return Object(a["x"])(),Object(a["f"])("div",ie,[Object(a["g"])("div",le,[ue,Object(a["i"])(l,{onSubmit:c.handleRegister,"validation-schema":n.schema},{default:Object(a["P"])(()=>[n.successful?Object(a["e"])("",!0):(Object(a["x"])(),Object(a["f"])("div",de,[Object(a["g"])("div",be,[me,Object(a["i"])(o,{name:"username",type:"text",class:"form-control"}),Object(a["i"])(i,{name:"username",class:"error-feedback"})]),Object(a["g"])("div",ge,[fe,Object(a["i"])(o,{name:"email",type:"email",class:"form-control"}),Object(a["i"])(i,{name:"email",class:"error-feedback"})]),Object(a["g"])("div",pe,[Oe,Object(a["i"])(o,{name:"password",type:"password",class:"form-control"}),Object(a["i"])(i,{name:"password",class:"error-feedback"})]),Object(a["g"])("div",he,[Object(a["g"])("button",{class:"btn btn-primary btn-block",disabled:n.loading},[Object(a["Q"])(Object(a["g"])("span",ve,null,512),[[a["L"],n.loading]]),Object(a["h"])(" Sign Up ")],8,je)])]))]),_:1},8,["onSubmit","validation-schema"]),n.message?(Object(a["x"])(),Object(a["f"])("div",{key:0,class:Object(a["r"])(["alert",n.successful?"alert-success":"alert-danger"])},Object(a["H"])(n.message),3)):Object(a["e"])("",!0)])])}var ye={name:"Register",components:{Form:se["c"],Field:se["b"],ErrorMessage:se["a"]},data(){const e=ae["a"]().shape({username:ae["b"]().required("Username is required!").min(3,"Must be at least 3 characters!").max(20,"Must be maximum 20 characters!"),email:ae["b"]().required("Email is required!").email("Email is invalid!").max(50,"Must be maximum 50 characters!"),password:ae["b"]().required("Password is required!").min(6,"Must be at least 6 characters!").max(40,"Must be maximum 40 characters!")});return{successful:!1,loading:!1,message:"",schema:e}},computed:{loggedIn(){return this.$store.state.auth.status.loggedIn}},mounted(){this.loggedIn&&this.$router.push("/profile")},methods:{handleRegister(e){this.message="",this.successful=!1,this.loading=!0,this.$store.dispatch("auth/register",e).then(e=>{this.message=e.message,this.successful=!0,this.loading=!1},e=>{this.message=e.response&&e.response.data&&e.response.data.message||e.message||e.toString(),this.successful=!1,this.loading=!1})}}};s("c74f");const we=I()(ye,[["render",ke],["__scopeId","data-v-43ad05e7"]]);var xe=we;const Se=()=>s.e("chunk-1f0cc288").then(s.bind(null,"66aa")),Ee=()=>s.e("chunk-4b00ff04").then(s.bind(null,"5535")),Pe=()=>s.e("chunk-cf2bffa6").then(s.bind(null,"0899")),_e=[{path:"/",name:"home",component:D},{path:"/home",component:D},{path:"/login",component:ce},{path:"/register",component:xe},{path:"/profile",name:"profile",component:Se},{path:"/admin",name:"admin",component:Ee},{path:"/user",name:"user",component:Pe}],Ie=Object(q["a"])({history:Object(q["b"])(),routes:_e});var Le=Ie,Ue=s("5502"),Me=s("bc3a"),Ae=s.n(Me);const Fe="http://localhost:8080/api/auth/";class qe{login(e){return Ae.a.post(Fe+"signin",{username:e.username,password:e.password}).then(e=>(e.data.accessToken&&localStorage.setItem("user",JSON.stringify(e.data)),e.data))}logout(){localStorage.removeItem("user")}register(e){return Ae.a.post(Fe+"signup",{username:e.username,email:e.email,password:e.password})}}var Ce=new qe;const He=JSON.parse(localStorage.getItem("user")),Te=He?{status:{loggedIn:!0},user:He}:{status:{loggedIn:!1},user:null},$e={namespaced:!0,state:Te,actions:{login({commit:e},t){return Ce.login(t).then(t=>(e("loginSuccess",t),Promise.resolve(t)),t=>(e("loginFailure"),Promise.reject(t)))},logout({commit:e}){Ce.logout(),e("logout")},register({commit:e},t){return Ce.register(t).then(t=>(e("registerSuccess"),Promise.resolve(t.data)),t=>(e("registerFailure"),Promise.reject(t)))}},mutations:{loginSuccess(e,t){e.status.loggedIn=!0,e.user=t},loginFailure(e){e.status.loggedIn=!1,e.user=null},logout(e){e.status.loggedIn=!1,e.user=null},registerSuccess(e){e.status.loggedIn=!1},registerFailure(e){e.status.loggedIn=!1}}},De=Object(Ue["a"])({modules:{auth:$e}});var Ne=De,Be=(s("4989"),s("ab8b"),s("ecee")),Re=s("ad3d"),Je=s("c074");Be["c"].add(Je["a"],Je["d"],Je["e"],Je["b"],Je["c"]),Object(a["c"])(F).use(Le).use(Ne).component("font-awesome-icon",Re["a"]).mount("#app")},8538:function(e,t,s){"use strict";s("2790")},afad:function(e,t,s){"use strict";s("b363")},b363:function(e,t,s){},b59b:function(e,t,s){"use strict";s("bcc5")},bcc5:function(e,t,s){},c74f:function(e,t,s){"use strict";s("eea7")},d19a:function(e,t,s){"use strict";s("de05")},de05:function(e,t,s){},eea7:function(e,t,s){}});
//# sourceMappingURL=app.d42d181a.js.map