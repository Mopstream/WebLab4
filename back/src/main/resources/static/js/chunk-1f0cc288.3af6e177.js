(window["webpackJsonp"]=window["webpackJsonp"]||[]).push([["chunk-1f0cc288"],{"1e3b":function(e,t,s){},"66aa":function(e,t,s){"use strict";s.r(t);var c=s("7a23");const n={key:0,class:"container"},r={class:"alert alert-success admin",role:"alert",style:{"text-align":"center"}},a={style:{display:"flex","justify-content":"space-between"}},l={class:"list-group",style:{width:"fit-content"}},i={class:"list-group-item d-flex align-items-center"},o=Object(c["g"])("strong",null,"Your id:",-1),g={class:"badge badge-primary badge-pill"},u={class:"list-group-item d-flex align-items-center"},b=Object(c["g"])("strong",null,"Your email:",-1),d={class:"badge badge-primary badge-pill"},p={class:"list-group-item d-flex align-items-center"},j=Object(c["g"])("strong",null,"Your authorities:",-1),O={class:"badge badge-info badge-pill"},h={class:"list-group-item d-flex align-items-center"},m=Object(c["g"])("strong",null,"Number of your points:",-1),f={class:"badge badge-success badge-pill"},y=Object(c["g"])("strong",null,"all",-1),v=Object(c["g"])("div",{class:"card",style:{width:"40%"}},[Object(c["g"])("img",{class:"card-img-top prof_image",alt:"Card image cap",style:{width:"100%",height:"100px"}}),Object(c["g"])("div",{class:"card-body"},[Object(c["g"])("p",{class:"card-text"},"Modern responsive design Vue.JS Senior Developer")])],-1);function w(e,t,s,w,x,k){return k.currentUser?(Object(c["x"])(),Object(c["f"])("div",n,[Object(c["g"])("div",r,[Object(c["g"])("strong",null,Object(c["H"])(k.currentUser.username),1),Object(c["h"])(" Profile ")]),Object(c["g"])("div",a,[Object(c["g"])("div",null,[Object(c["g"])("ul",l,[Object(c["g"])("li",i,[o,Object(c["g"])("span",g,Object(c["H"])(k.currentUser.id),1)]),Object(c["g"])("li",u,[b,Object(c["g"])("span",d,Object(c["H"])(k.currentUser.email),1)]),Object(c["g"])("li",p,[j,Object(c["g"])("span",O,Object(c["H"])(k.currentUser.roles[0]),1)]),Object(c["g"])("li",h,[m,Object(c["g"])("span",f,Object(c["H"])(x.points.length),1),Object(c["g"])("button",{type:"button",class:"btn btn-outline-danger",onClick:t[0]||(t[0]=e=>k.deletePoints())},[Object(c["h"])(" Delete "),y,Object(c["h"])(" your points")])])])]),v])])):Object(c["e"])("",!0)}s("14d9");var x=s("b697"),k={name:"Profile",data(){return{points:[]}},computed:{currentUser(){return this.$store.state.auth.user}},methods:{getPoints(){x["a"].getAll().then(e=>{this.points=e.data}).catch(e=>console.error(e))},deletePoints(){x["a"].deleteAll(),this.points=[]}},mounted(){this.currentUser||this.$router.push("/login"),this.getPoints()}},P=(s("aaa7"),s("6b0d")),U=s.n(P);const A=U()(k,[["render",w]]);t["default"]=A},aaa7:function(e,t,s){"use strict";s("1e3b")},b697:function(e,t,s){"use strict";var c=s("bc3a"),n=s.n(c),r=s("c4c6");const a="http://localhost:8080/api/points/";class l{getAll(){return n.a.get(a+"",{headers:Object(r["a"])()})}savePoint(e){return n.a.post(a,e,{headers:Object(r["a"])()})}deleteAll(){return n.a.delete(a,{headers:Object(r["a"])()})}}t["a"]=new l},c4c6:function(e,t,s){"use strict";function c(){let e=JSON.parse(localStorage.getItem("user"));return e&&e.accessToken?{Authorization:"Bearer "+e.accessToken}:{}}s.d(t,"a",(function(){return c}))}}]);
//# sourceMappingURL=chunk-1f0cc288.3af6e177.js.map