var TexLinebreak = (() => {
  var __create = Object.create;
  var __defProp = Object.defineProperty;
  var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
  var __getOwnPropNames = Object.getOwnPropertyNames;
  var __getProtoOf = Object.getPrototypeOf;
  var __hasOwnProp = Object.prototype.hasOwnProperty;
  var __commonJS = (cb, mod) => function __require() {
    return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
  };
  var __export = (target, all) => {
    for (var name in all)
      __defProp(target, name, { get: all[name], enumerable: true });
  };
  var __copyProps = (to, from, except, desc) => {
    if (from && typeof from === "object" || typeof from === "function") {
      for (let key of __getOwnPropNames(from))
        if (!__hasOwnProp.call(to, key) && key !== except)
          __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
    }
    return to;
  };
  var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
    // If the importer is in node compatibility mode or this is not an ESM
    // file that has been converted to a CommonJS file using a Babel-
    // compatible transform (i.e. "__esModule" has not been set), then set
    // "default" to the CommonJS "module.exports" for node compatibility.
    isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
    mod
  ));
  var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

  // node_modules/hyphenation.en-us/lib/en-us.js
  var require_en_us = __commonJS({
    "node_modules/hyphenation.en-us/lib/en-us.js"(exports, module) {
      module.exports = {
        "id": ["en-us", "en"],
        "leftmin": 2,
        "rightmin": 3,
        "patterns": {
          3: "x1qei2e1je1f1to2tlou2w3c1tue1q4tvtw41tyo1q4tz4tcd2yd1wd1v1du1ta4eu1pas4y1droo2d1psw24sv1dod1m1fad1j1su4fdo2n4fh1fi4fm4fn1fopd42ft3fu1fy1ga2sss1ru5jd5cd1bg3bgd44uk2ok1cyo5jgl2g1m4pf4pg1gog3p1gr1soc1qgs2oi2g3w1gysk21coc5nh1bck1h1fh1h4hk1zo1ci4zms2hh1w2ch5zl2idc3c2us2igi3hi3j4ik1cab1vsa22btr1w4bp2io2ipu3u4irbk4b1j1va2ze2bf4oar1p4nz4zbi1u2iv4iy5ja1jeza1y1wk1bk3fkh4k1ikk4k1lk1mk5tk1w2ldr1mn1t2lfr1lr3j4ljl1l2lm2lp4ltn1rrh4v4yn1q1ly1maw1brg2r1fwi24ao2mhw4kr1cw5p4mkm1m1mo4wtwy4x1ar1ba2nn5mx1ex1h4mtx3i1muqu2p3wx3o4mwa1jx3p1naai2x1ua2fxx4y1ba2dn1jy1cn3fpr2y1dy1i",
          4: "4dryn2itni4on1inn1im_up3nik4ni4dy5giye4tyes4_ye44ab_nhe4nha4abe2n2gyn1guy1ery5eep2pe4abry3lay3lone4wne4v1nesy3chn1erne2q3neo1nenp2seps4hy2cey5lu2nedne2cyme44nk2y5at2adine2b2ne_y5ac2p1tp2ten1den1cun1cryn5dp2th4adup4twpub3ae4rxu3ayn5gaff4pue4n2au4p1ppuf4n2atag1ipu4mag1na2gon4asx3tix1t2pu2na4gya3haa3heah4la3ho_ti2a5ian2an5puspu2tnak4_th2n1kl_te4_ta4mu4u4mupmun23mum2alex4ob_sy25ynxal1i_st4y1o4xi5cxi5a4alm_si2_sh2m5sixhu4m4sh4m3r4amam2py2rabm2pixhi2yo5dr2ai4m1pmo2vmos2x2edmo2r4n1la2mor2asx3c2xas5yom4x4apxam3nme44mokrbi2nne44andy4osp4ot3noemn4omn4a4m1n4nog4m1l2angws4l1posw3shwri4wra4yp3iwom11wo2m2izrb4ow4nopo4pr2cem2isrd2iano4mig4y3pomi3awiz55mi_no4n4m1fme4v2re_wir42mes1menme2mme2gre1o2med4me_4nop4m5c4m1bwil21noureu2whi4w3ev4maprev2w1era2plpo4crfu4r4fyy5pu2maha3pu2mab2a2rn1p4npi44lyb4lya2p3nwam42l1w1lut4luplu3or1glluf4lu5a2wacltu2y3rol1tr4vv4r3guyr4rl1te4rh_nru4ar1il2sel4sc4l1rl5prl4plys4c4lovri3ar4ib4lof3lo_ar2par3q_os3ll4oll2i4as_ri1o3vokl2levoi44p1mlka35vo_ns4cas4ll1izr4iqr2is3vivl1it3lika2tan2sen2slrle42l3hlgo3l5gal5frns3mvi4p3ley_od2r2meles24athr4myle2al3drv1inldi4l2de2vilnt2il3civik4lce42l1b4lavv3ifrno4r3nua1trr2ocnt4sy4sok4syks4la2tuk4sck3ouko5ryss4a2tyau4b4klyys1tnu1akis4au3rki4pro4ek4ima2va5ki_nu4dn4umn3uokes4k1erav1irok2ke4g1keek2ed_me2aw3ikal4aws4k5agk3ab3ka_aye4ays4veg3jo4p5ba_4vedjew3n1v24ve_ja4pzar23vatizi4n1w41batba4z2b1bb2beix4o4i5w4b1d4be_rox5nym4nyp4n3za4ittr3por1r4i1ti1bel2ith2itei2su4rs2r1sars4cr2seis1p3betvag4i2sor1shbe3wr1sioad34b3hbi2bbi4d3bie3isf4ise2is_1bilr1sp5va_r5sw_le2uz4eir1ibi2tuxu3r1tiu1v2i1raze4nze4pb2l2uu4mo1biip3iz1eripe4b4louts44b1m4b3no3br3bodi4osbo4eru3aio4mi1ol4io_3booo1ce4inyin1u2insru2n2inn4inl4inkrv4e2inioch42iner3vo4indpi2np4idbt4lb4tob3trry4cry3t2in_o4elbu4ni2muim1i5saiil3v4ilnil1iil5fs1apo3er4b5w5by_bys4_in1sau4i1lazet4u2suo3ev2z1ii2go4igius1p5saw4s5bo2fi4ifti3fl4if_i3etsch2usc22ie4i2dui4dri2diid5dpi3au3ruz4ils1cuz4is4s5d4se_se4a2ce_2ici4ich3ceii1bri5bo1ceni1blse2g5seiibe43cepi2aniam4ur2li2al2i1acet4hy2scew41phy4ch_5phuhu4thu4gche2h4tyh4shur1durc44hr44h5p5sev5sexu1ra4s3fup3p2s3gph3t2sh_ho4g2h1n_he23ciau3pl4h1mci5ch2lozo4m4ciihi2vhi4p2cim2cin4phsu1peu1ouo1geu5osheu4sho4he4th1es4shwun5zun5ysi1bunu45cizo4glck3ihep5he2nh4ed1sioph2l5hazsi2rcly4zte4_ge21siscoe22cog5siu1siv5siz_ga24skes1l2s2leha4m2s1ms3ma1ogyo1h2u1ni3gus3gun2guegu4acov1gth3_eu3g4ros1n4_es3u2nez4zyum2pu1mi3som_ev2oig4cri2gov15goos4opgon2ul5v5goeu3lugob53go_2c1t4ph_g1nog1nic2te4sov4ulsgn4ag4myc4twcud5c4ufc4uipe2t3glo1gleul2igla4_eg23giz3cun5givgi4u3gir5gio1cusul4e2spagil4g1ic5gi__eb4cze41d2a5da_u1laggo44daf2dagg2gege4v1geo1gen2ged3dato1la2ge_ol2dol2i5daypek4p4eed1d42de_4gazol2tuiv3ol2vo2lys1sa2gamgaf4o2meui4n2ui2pe2cd4em4fugi4jku3fl3ufaf2tyf4to1denu4du4pe_2f3sfri2de1ps1si4f5pfos5d3eqs4sls4snfo2rss2tdes25fon4p1b_ci23payss5w2st_de1tf4l2de1v2fin4dey4d1fd4gast2idg1id2gyd1h25di_ud5dfi3au4cy_ch4pav43didu3cud1iff2fyu3crd1inst4r4f1ffev4fer11dio2fedfe4bdir2s2ty4fe_dis1on1au3ca4f5bon1c2ondd5k25far4fagpa1peys45eyc1exps4ul2dlyp4ale3whon3s3do_e1wa5doee5vud4oge1visu2msu2nub4euav4su2rp4ai6rk_d4or3dosu1atdo4v3doxp4adoo4k4swoo2padre4eus4e3upe5un2ophet5z4syc3syl4y3hoy1ads4pd4swd4syd2tho4wo3ta_du2c4etn2tabta2luac4es4wdu4g2ess4uabdu4n4duptav4st5bow1io1pr5dyn2tawe1sp2t1bop1uead1tz4et4chopy5ea4l4t1d4te_2tyle1si4esh1tee4tyat1cr4twoteg4es2c4eru1teoer1s2eroea2tte4po1rat1wh3tusea2v3teu3texer1i2e1ber1h4tey2t1f4t1ge3br2th_th2e4thle1ce3tumec2i2ths2erb1tia4tueer1aou5vtud2tif22tige1potu1aou4lttu41timt5toos4le1cre2pat4swe5owe1cue4ottsh4eos4e1ort4sce3ol4edieo2ge5of1tio4eno4enn5tiq4edoti4u1tive3my1tiz4othee2ct5laee2ft5lo4t1mee2mtme4e1meem5bcoi4to3be5exo1ry2tof1effel2iel2ftos24t1pe1la1traos2ceig2ei5de5ico2soe1h45egyeg5n",
          5: "_ach4e4go_e4goseg1ule5gurtre5feg4iceher4eg5ibeger44egaltre4mei5gle3imbe3infe1ingtra3beir4deit3eei3the5ity5triae4jud3efiteki4nek4la2trime4la_e4lactri4v4toute4law5toure3leaefil45elece4ledto2rae5len4tonye1lestro3ve4fic4tonoto3mytom4bto2mato5ice5limto2gre3lioe2listru5i4todo4ellaee4tyello4e5locel5ogeest4el2shel4tae5ludel5uge4mace4mage5man2t1n2ee2s4ee4p1e2mele4metee4naemi4eee4lyeel3i3tled3tle_e4mistlan4eed3iem3iztrus4emo4gti3zaem3pie4mule4dulemu3ne4dritiv4aedon2e4dolti3tle5neae5neeen3emtis4pti5sotis4m3tisee3newti3sae5niee5nile3nioedi5zen3ite5niu5enized1ited3imeno4ge4nosen3oven4swti5oc4t1s2en3uaen5ufe3ny_4en3zed3ibe3diae4oi4ede4s3tini4ed3deo3ret2ina2e2dae4culeo4toe5outec4te4t3t2t4tes2t1ine5pel4timpe2corephe4e4plie2col5tigutu3arti5fytu4bie3pro3tienep4sh5tidie4putt4icoeci4t4tick2ti2bec3imera4bti4aber3ar4tuf45tu3ier4bler3che4cib2ere_4thooecca54thil3thet4thea3turethan4e4cade4bitere4qe4ben5turieret4tur5oeav5oeav5itu5ry4tess4tes_ter5ve1rio4eriter4iueri4v1terier3m4ter3cte5pe4t1waer3noeast3er5obe5rocero4rer1oue3assea5sp1tent4ertler3twtwis4eru4t3tende1s4a3tenc5telsear2te2scateli4e3scres5cue1s2ee2sec3tel_te5giear5kear4cte5diear3ae3sha2t1ede5ande2sice2sid5tecttece44teattype3ty5phesi4uea4gees4mie2sole3acte2sone1a4bdys5pdy4sedu4petaun4d3uleta5sytas4e4tare4tarctar4ata5pl2estrta5mo4talke2surtal3idu5eleta4bta5lae3teoua5naet1ic4taf4etin4ta5doe5tir4taciuan4id1ucad1u1ae3trae3tre2d1s2syn5ouar2d4drowet3uaet5ymdro4pdril4dri4b5dreneu3rouar3ieute44draieu5truar3te2vasdop4pe5veadoo3ddoni4u4belsum3iev1erdoli4do4laev3idevi4le4vinevi4ve5voc2d5ofdo5dee4wage5wee4d1n4ewil54d5lue3wit2d3lou3ber5eye_u1b4i3dledfa3blfab3rfa4ce3dle_fain4suit3su5issu2g34d5lasu4b3fa3tasu1al4fato1di1vd2iti5disiuci4bfeas4di1redi4pl4feca5fectdio5gfe3life4mofen2d4st3wuc4it5ferr5diniucle3f4fesf4fie4stry1dinaf4flydi3ge3dictd4icedia5bs4tops1tle5stirs3tifs4ties1ticfic4is5tias4ti_4ficsfi3cuud3ers3thefil5iste2w4filyudev45finas4tedfi2nes2talfin4ns2tagde2tode4suflin4u1dicf2ly5ud5isu5ditde1scd2es_der5sfon4tu4don5dermss4lid4erhfor4is4siede2pudepi4fra4tf5reade3pade3nufril4frol5ud4side3nou4eneuens4ug5infu5el5dem_s5setfu5nefu3rifusi4fus4s4futade5lode5if4dee_5gal_3galiga3lo2d1eds3selg5amos2s5cssas3u1ing4ganouir4mgass4gath3uita4deaf5dav5e5dav44dato4darygeez44spotspor4s4pon4gelydark5s4ply4spio4geno4genydard5ge3omg4ery5gesigeth54getoge4tydan3g4g1g2da2m2g3gergglu5dach4gh3inspil4gh4to4cutr1gi4agia5rula5bspho5g4icogien5s2pheulch42sperspa4n5spai3c4utu1lenul4gigir4lg3islcu5pycu3picu4mic3umecu2maso5vi5glasu5liagli4bg3lig5culiglo3r4ul3mctu4ru1l4og4na_c3terul1tig2ning4nio4ultug4noncta4b4c3s2cru4dul5ulsor5dgo3isum5absor5ccris4go3nic4rinson4gsona45gos_cri5fcre4vum4bi5credg4raigran25solvsoft3so4ceunat44graygre4nco5zi4gritcoz5egruf4cow5ag5stecove4cos4es5menun4ersmel44corbco4pl4gu4tco3pacon5tsman3gy5racon3ghach4hae4mhae4th5aguha3lac4onecon4aun4ims3latu2ninhan4gs3ket5colocol5ihan4kuni3vhap3lhap5ttras4co4grhar2dco5agsir5aclim45sionhas5shaun44clichaz3acle4m1head3hearun3s4s3ingun4sws2ina2s1in4silysil4eh5elohem4p4clarhena45sidiheo5r1c4l4h4eras5icc2c1itu4orsh3ernshor4h3eryci3phshon34cipecion45cinoc1ingc4inahi5anhi4cohigh5h4il2shiv5h4ina3ship3cilihir4lhi3rohir4phir4rsh3iohis4ssh1inci4lau5pia4h1l4hlan44cier5shevcia5rhmet4ch4tish1erh5ods3cho2hoge4chi2z3chitho4mahome3hon4aho5ny3hoodhoon45chiouptu44ura_ho5ruhos4esew4ihos1p1housu4ragses5tu4rasur4behree5se5shs1e4s4h1s24chedh4tarht1enht5esur4fru3rifser4os4erlhun4tsen5gur1inu3riosen4dhy3pehy3phu1ritces5tur3iz4cesa4sencur4no4iancian3i4semeia5peiass45selv5selfi4atu3centse1le4ceniib5iaib3inseg3ruros43cencib3li3cell5cel_s5edli5bun4icam5icap4icar4s4ed3secticas5i4cayiccu44iceour4pe4ced_i5cidsea5wi2cipseas4i4clyur4pi4i1cr5icrai4cryic4teictu2ccon4urti4ic4umic5uoi3curcci4ai4daiccha5ca4thscof4ide4s4casys4cliscle5i5dieid3ios4choid1itid5iui3dlei4domid3owu5sadu5sanid5uous4apied4ecany4ield3s4cesien4ei5enn4sceii1er_i3esci1estus3ciuse5as4cedscav5if4frsca4pi3fieu5siau3siccan4eiga5bcan5d4calous5sli3gibig3ilig3inig3iti4g4lus1trig3orig5oti5greigu5iig1ur2c5ah4i5i44cag4cach4ca1blusur4sat3usa5tab5utoi3legil1erilev4uta4b4butail3iail2ibil3io3sanc2ilitil2izsal4t5bustil3oqil4tyil5uru3tati4magsa5losal4m4ute_4imetbu3res3act5sack2s1ab4imitim4nii3mon4utelbumi4bu3libu4ga4inav4utenbsor42b5s2u4tis4briti3neervi4vr3vic4inga4inger3vey4ingir3ven4ingo4inguu4t1li5ni_i4niain3ioin1isbo4tor5uscrunk5both5b5ota5bos42i1no5boriino4si4not5borein3seru3in2int_ru4glbor5di5nusut5of5bor_uto5gioge4io2grbon4au5tonru3enu4touion3iio5phior3ibod3iio5thi5otiio4toi4ourbne5gb3lisrt4shblen4ip4icr3triip3uli3quar4tivr3tigrti4db4le_b5itzira4bi4racird5ert5ibi4refbi3tri4resir5gibi5ourte5oir4isr3tebr4tagbin4diro4gvac3uir5ul2b3ifis5agis3arisas52is1cis3chbi4eris3erbi5enrson3be5yor5shais3ibisi4di5sisbe3tw4is4krs3es4ismsbe5trr3secva4geis2piis4py4is1sbe3sp4bes4be5nuval5ois1teis1tirrys4rros44be5mis5us4ita_rron4i4tagrri4vi3tani3tatbe3lorri4or4reoit4esbe1libe5gu4itiarre4frre4cbe3giit3igbe3dii2tim2itio4itisrp4h4r3pet4itonr4peait5rybe3debe3dai5tudit3ul4itz_4be2dbeat3beak4ro4varo4tyros4sro5roiv5ioiv1itror3i5root1roomval1ub3berva5mo4izarva5piron4eban3ijac4qban4ebal1ajer5srom4prom4iba4geazz5i5judgay5alax4idax4ickais4aw4ly3awaya1vorav5ocav3igke5liv3el_ve4lov4elyro1feke4tyv4erdv4e2sa5vanav3ag5k2ick4illkilo5au1thk4in_4ves_ro3crkin4gve4teaun5dk5ishau4l2au3gu4kleyaugh3ve4tyk5nes1k2noat3ulkosh4at5uekro5n4k1s2at5uaat4that5te5vianat4sk5vidil4abolaci4l4adela3dylag4nlam3o3landrob3la4tosr4noular4glar3ilas4ea4topr3nivr3nita2tomr5nica4toglbin44l1c2vi5gnat3ifat1ica5tiar3neyr5net4ati_ld5isat4hol4driv2incle4bileft55leg_5leggr4nerr3nel4len_3lencr4nar1lentle3phle4prvin5dler4e3lergr3mitl4eroat5evr4mio5lesq3lessr3menl3eva4vingrma5cvio3lvi1ou4leyevi5rovi3so4l1g4vi3sulgar3l4gesate5cat5apli4agli2amr3lo4li4asr4lisli5bir4ligr2led4lics4vitil4icul3icyl3idaat5ac3lidirk4lel4iffli4flr3ket3lighvit3r4vityriv3iri2tulim3ili4moris4pl4inar3ishris4clin3ir4is_li5og4l4iqlis4pas1trl2it_as4shas5phri2pla4socask3ia3sicl3kallka4ta3sibl4lawashi4l5leal3lecl3legl3lel5riphas4abar2shrin4grin4ear4sarin4dr2inal5lowarre4l5met3rimol4modlmon42l1n2a3roorim5ilo4civo4la5rigil5ogo3loguri5et5longlon4iri1erlood5r4icolop3il3opmlora44ricir4icerib3a5los_v5oleri4agria4blos4tlo4taar2mi2loutar2izar3iolpa5bl3phal5phi4rhall3pit5voltar4im3volv2l1s2vom5ivori4l4siear4fllt5agar4fivo4rylten4vo4talth3ia3reeltis4ar4drw5ablrgo4naraw4lu3brluch4lu3cilu3enwag5olu5idlu4ma5lumia5raur5gitwait5luo3rw5al_luss4r5gisar4atl5venrgi4nara3pwar4tar3alwas4tly5mely3no2lys4l5ysewa1teaque5ma2car3gicma4clr3get5magnwed4nmaid54maldrg3erweet3wee5vwel4lapoc5re4whwest3ap3in4aphires2tr4es_mar3vre5rumas4emas1t5matemath3rero4r4eriap5atr1er4m5bilre1pumbi4vapar4a5nuran3ul4med_an3uare5lure1lian4twre5itmel4tan2trre4fy4antomen4are3fire2fe4menemen4imens4re1de3ment2r2edme5onre4awwin4g5reavme4tare3anme1tere1alm4etr3wiserdin4rdi4aan4stwith3an2span4snan2samid4amid4gan5otwl4esr4dalm4illmin4a3mindrcum3rc4itr3charcen4min4tm4inumiot4wl3ina3niumis5lan3ita3nip4mithan3ioan1gla3neuws4per2bina3nena5neem4ninw5s4tan1dl4mocrrbi4fmo2d1mo4gomois2xac5ex4agor4bagmo3mer4baba3narrau4ta5monrare4rar5cra5nor4aniam1inr2amiam5ifra4lomo3spmoth3m5ouf3mousam3icxer4ixe5roraf4tr5aclm3petra3bixhil5mpi4aam3ag3quetm5pirmp5is3quer2que_qua5vmpov5mp4tram5ab3alyz4m1s25alyt4alysa4ly_ali4exi5di5multx4ime4aldia4laral3adal5abak1enain5opu3trn4abu4nac_na4can5act5putexpe3dna4lia4i4n4naltai5lya3ic_pur4rag5ulnank4nar3c4narenar3inar4ln5arm3agognas4c4ag4l4ageupul3cage4oaga4na4gab3nautnav4e4n1b4ncar5ad5umn3chaa3ducptu4rpti3mnc1innc4itad4suad3owad4len4dain5dana5diua3ditndi4ba3dion1ditn3dizn5ducndu4rnd2we3yar4n3eara3dianeb3uac4um5neckac3ulp4siba3cio5negene4laac1inne5mine4moa3cie4nene4a2cine4poyc5erac1er2p1s2pro1tn2erepro3lner4rych4e2nes_4nesp2nest4neswpri4sycom4n5evea4carab3uln4gabn3gelpre3vpre3rycot4ng5han3gibng1inn5gitn4glangov4ng5shabi5an4gumy4erf4n1h4a5bannhab3a5bal3n4iani3anni4apni3bani4bl_us5ani5dini4erni2fip3petn5igr_ure3_un3up3per_un5op3pennin4g_un5k5nis_p5pel_un1en4ithp4ped_un1ani3tr_to4pympa3_til4n3ketnk3inyn5ic_se2ny4o5gy4onsnmet44n1n2_ru4d5pounnni4vnob4lpo4tan5ocly4ped_ro4qyper5noge4pos1s_ri4gpo4ry1p4or_res2no4mono3my_ree2po4ninon5ipoin2y4poc5po4gpo5em5pod_4noscnos4enos5tno5tayp2ta3noun_ra4cnowl3_pi2tyra5m_pi4eyr5ia_out3_oth32n1s2ns5ab_or3t_or1d_or3cplu4mnsid1nsig4y3s2eys3ion4socns4pen5spiploi4_odd5nta4bpli4n_ni4cn5tib4plignti2fpli3a3plannti4p1p2l23ysis2p3k2ys3ta_mis1nu5enpi2tun3uinp3ithysur4nu1men5umi3nu4nyt3icnu3trz5a2b_li4t_li3o_li2n_li4g_lev1_lep5_len4pion4oard3oas4e3pi1ooat5ip4inoo5barobe4l_la4mo2binpind4_ju3rob3ul_is4i_ir5rp4in_ocif3o4cil_in3so4codpi3lopi3enocre33piec5pidipi3dep5ida_in2kod3icodi3oo2do4odor3pi4cypian4_ine2o5engze3rooe4ta_im3m_id4l_hov5_hi3b_het3_hes3_go4r_gi4bpho4ro5geoo4gero3gie3phobog3it_gi5azo5ol3phizo4groogu5i4z1z22ogyn_fes3ohab5_eye55phieph1icoiff4_en3sph4ero3ing_en3go5ism_to2qans3v_el5d_eer4bbi4to3kenok5iebio5mo4lanper1v4chs_old1eol3erpe5ruo3letol4fi_du4co3liaper3op4ernp4erio5lilpe5ono5liop4encpe4la_do4tpee4do5livcin2q3pediolo4rol5pld3tabol3ub3pedeol3uno5lusedg1le1loaom5ahoma5l2p2edom2beom4bl_de3o3fich3pe4ao4met_co4ro3mia_co3ek3shao5midom1inll1fll3teapa2teo4monom3pi3pare_ca4tlue1pon4aco3nanm2an_pa4pum2en_on5doo3nenng1hoon4guon1ico3nioon1iso5niupa3nypan4ao3nou_bri2pain4ra1oronsu4rk1hopac4tpa4ceon5umonva5_ber4ood5eood5i6rks_oop3io3ordoost5rz1scope5dop1erpa4ca_ba4g_awn4_av4i_au1down5io3pito5pon1sync_as1s_as1p_as3ctch1c_ar5so5ra_ow3elo3visov4enore5auea1mor3eioun2d_ant4orew4or4guou5etou3blo5rilor1ino1rio_ang4o3riuor2miorn2eo5rofoto5sor5pe3orrhor4seo3tisorst4o3tif_an5cor4tyo5rum_al3tos3al_af1tos4ceo4teso4tano5scros2taos4poos4paz2z3wosi4ue3pai",
          6: "os3ityos3itoz3ian_os4i4ey1stroos5tilos5titxquis3_am5atot3er_ot5erso3scopor3thyweek1noth3i4ot3ic_ot5icao3ticeor3thiors5enor3ougor3ityor3icaouch5i4o5ria_ani5mv1ativore5sho5realus2er__an3teover3sov4erttot3icoviti4o5v4olow3dero4r3agow5esto4posiop3ingo5phero5phanthy3sc3operaontif5on3t4ionten45paganp3agattele2gonspi4on3omyon4odipan3elpan4tyon3keyon5est3oncil_ar4tyswimm6par5diompro5par5elp4a4ripar4isomo4gepa5terst5scrpa5thy_atom5sta1tio5miniom3icaom3ic_ss3hatsky1scpear4lom3ena_ba5naol3umer1veilpedia4ped4icolli4er1treuo5liteol3ishpeli4epe4nano5lis_pen4thol3ingp4era_r1thoup4erago3li4f_bas4er1krauperme5ol5id_o3liceper3tio3lescolass4oi3terpe5tenpe5tiz_be5raoi5son_be3smphar5iphe3nooi5letph4es_oi3deroic3esph5ingr3ial_3ognizo5g2ly1o1gis3phone5phonio5geneo4gatora3mour2amenofit4tof5itera3chupi4ciepoly1eod5dedo5cureoc3ula1pole_5ocritpee2v1param4oc3raco4clamo3chetob5ingob3a3boast5eoke1st3nu3itpi5thanuf4fentu3meoerst2o3chasplas5tn3tinepli5ernti4ernter3sntre1pn4s3esplum4bnsati4npre4cns4moonon1eqnor5abpo3et5n5lessn5oniz5pointpoly5tnon4agnk3rup3nomicng1sprno5l4inois5i4n3o2dno3blenni3aln5keroppa5ran3itor3nitionis4ta5nine_ni3miznd3thrmu2dron3geripray4e5precipre5copre3emm3ma1bpre4lan5gerep3rese3press_can5cmedi2c5pri4e_ce4la3neticpris3op3rocal3chain4er5ipros3en4erarnera5bnel5iz_cit5rne4gatn5d2ifpt5a4bjanu3aign4itn3chisn5chiln5cheon4ces_nau3seid4iosna3talnas5tinan4itnanci4na5mitna5liahnau3zput3er2n1a2bhex2a3hatch1multi3hair1sm4pousg1utanmpo3rim4p1inmp5iesmphas4rach4empar5iraf5figriev1mpara5mo5seyram3et4mora_rane5oran4gemo3ny_monol4rap3er3raphymo3nizgno5morar5ef4raril1g2nacg1leadmoni3ara5vairav3elra5ziemon5gemon5etght1wemoi5sege3o1dmma5ryr5bine3fluoren1dixmis4ti_de3ra_de3rie3chasrch4err4ci4bm4inglm5ineedu2al_3miliame3tryrdi4er_des4crd3ingdi2rerme5thimet3alre5arr3mestim5ersadi2rende2ticdes3icre4cremen4temensu5re3disred5itre4facmen4dede2mosmen5acmem1o3reg3ismel5onm5e5dyme3died2d5ibren4te5mediare5pindd5a5bdata1bmba4t5cle4arma3tisma5scemar4lyre4spichs3huma5riz_dumb5re3strre4terbrus4qre3tribio1rhre5utiman3izre4valrev3elbi1orbbe2vie_eas3ire5vilba1thyman5is5maniamal4tymal4lima5linma3ligmag5inav3ioul5vet4rg3inglus3teanti1dl5umn_ltur3a_el3emltera4ltane5lp5ingloun5dans5gra2cabllos5etlor5ouric5aslo5rie_enam35ricidri4cie5lope_rid5erri3encri3ent_semi5lom3errig5an3logicril3iz5rimanlob5allm3ingrim4pell5out5rina__er4ril5linal2lin4l3le4tl3le4nriph5eliv3er_ge5og_han5k_hi3er_hon3olin3ea1l4inel4im4p_idol3_in3ci_la4cy_lath5rit3iclim4blrit5urriv5elriv3et4l4i4lli4gra_leg5elif3errk4linlid5er4lict_li4cor5licioli4atorl5ish_lig5a_mal5o_man5a_mer3c5less_rm5ersrm3ingy3thinle5sco3l4erilera5b5lene__mon3ele4matld4erild4erela4v4ar1nis44lativ_mo3rola5tanlan4telan5etlan4dllab3ic_mu5takin4dek3est_ro5filk3en4dro5ker5role__of5te4jestyys3icaron4al5izont_os4tlron4tai4v3ot_pe5tero3pelrop3ici5voreiv5il__pio5n_pre3mro4the_ran4tiv3en_rov5eliv3ellit3uati4tramr5pentrp5er__rit5ui4tismrp3ingit5ill_ros5tit3ica4i2tici5terirre4stit3era4ita5mita4bi_row5dist4lyis4ta_is4sesrsa5tiissen4is4sal_sci3erse4crrs5er_islan4rse5v2yo5netish5opis3honr4si4bis5han5iron_ir4minrtach4_self5iri3turten4diri5dei4rel4ire4de_sell5r4tieriq3uidrtil3irtil4lr4tilyr4tistiq5uefip4re4_sing4_ting4yn3chrru3e4lion3at2in4th_tin5krum3pli4no4cin3ityrun4ty_ton4aruti5nymbol5rvel4i_top5irv5er_r5vestin5geni5ness_tou5s_un3cein3cerincel45ryngei4n3auim3ulai5miniimi5lesac3riim5ida_ve5rasalar4ima5ryim3ageill5abil4istsan4deila5rai2l5am_wil5ii4ladeil3a4bsa5voright3iig3eraab5erd4ific_iff5enif5eroi3entiien5a45ie5gaidi5ou3s4cieab5latidi4arid5ianide3al4scopyab5rogid5ancic3ulaac5ardi2c5ocic3ipaic5inase2c3oi4carai4car_se4d4ei2b5riib5iteib5it_ib5ertib3eraac5aroi4ativ4ian4tse4molsen5ata5ceouh4warts5enedhus3t4s5enin4sentd4sentlsep3a34s1er_hun5kehu4min4servohro3poa5chethov5el5se5umhouse3sev3enho5senhort3eho5rishor5at3hol4ehol5arh5odizhlo3riac5robhis3elhion4ehimer4het4edsh5oldhe2s5ph5eroushort5here5aher4bahera3p3side_5sideshen5atsi5diz4signahel4lyact5ifhe3l4ihe5do55sine_h5ecathe4canad4dinsion5aad5er_har4lehard3e3sitioha5rasha3ranhan4tead3icahang5oadi4ersk5inesk5ing5hand_han4cyhan4cislith5hala3mh3ab4lsmall32g5y3n5gui5t3guard5smithad5ranaeri4eag5ellag3onia5guerso4labsol3d2so3licain5in4grada3s4on_gor5ougo5rizgondo5xpan4dait5ens5ophyal3end3g4o4ggnet4tglad5i5g4insgin5ge3g4in_spen4d2s5peog3imen5gies_3spher5giciagh5outsp5ingge5nizge4natge5lizge5lisgel4inxi5miz4gativgar5n4a5le5oga3nizgan5isga5mets5sengs4ses_fu4minfres5cfort5assi4erss5ilyfore5tfor5ayfo5ratal4ia_fon4dessur5aflo3ref5lessfis4tif1in3gstam4i5stands4ta4p5stat_fin2d5al5levs5tero4allicstew5afight5fi5del5ficie5ficiafi3cer5stickf3icena5log_st3ingf3icanama5ra5stockstom3a5stone2f3ic_3storef2f5iss4tradam5ascs4trays4tridf5fin_fend5efeath3fault5fa3thefar5thfam5is4fa4mafall5eew3inge5verbeven4ie5vengevel3oev3ellev5asteva2p5euti5let5roset3roget5rifsy5rinet3ricet5onaam5eraam5ilyami4noamor5ieti4noe5tidetai5loethod3eten4dtal5enes5urramp5enan3ageta5loge5strotan4detanta3ta5pere3ston4es2toes5times3tigta3rizestan43analy4taticta4tures4prean3arces3pertax4ises5onaes3olue5skintch5etanar4ies4i4ntead4ie2s5ima3natiande4sesh5enan3disan4dowang5iete5geres5ences5ecres5cana4n1icte2ma2tem3at3tenanwrita45erwau4tenesert3era3nieser3set5erniz4erniter4nis5ter3de4rivaan3i3fter3isan4imewo5vener3ineeri4ere3rient3ess_teth5e5ericke1ria4er3ester5esser3ent4erenea5nimier5enaer3emoth3easthe5atthe3iser5el_th5ic_th5icaere3in5thinkere5coth5odea5ninee3realan3ishan4klier4che5anniz4erandti4atoanoth5equi3lep5utat4ic1uan4scoe4probep3rehe4predans3poe4precan4surantal4e3penttim5ulep5anceo5rol3tine_eop3aran4tiewin4deap5eroen3ishen5icsen3etren5esten5esien5eroa3pheren3dicap3itae4nanten5amoem5ulaa3pituti3zen5emnize5missem5ishap5olaem5ine3tles_t5let_em1in2apor5iem3icaem5anael3op_el4labapos3te3liv3el5ishaps5esweath3e3lierel3icaar3actwa5verto3nate3libee4l1erel3egato3rietor5iza5radeelaxa4aran4gto3warelan4dej5udie5insttra5chtraci4ar5av4wa5gere5git5arbal4ar5easeg5ing4voteetrem5iar3enta5ressar5ial4tricsvor5abe3finetro5mitron5i4tronyar3iantro3sp5eficia3rieted5uloed3icae4d1erec3ulaec4tane4cremeco5roec3orae4concar5o5de4comme4cluse4clame5citeec5ifya5ronias3anta5sia_tu4nis2t3up_ecan5ce4belstur3ise4bel_eav3ene4a3tue5atifeath3ieat5eneart3eear4ilear4icear5eseam3ereal3oueal5erea5geread5iedum4be4ducts4duct_duc5eras3tenasur5adrea5rat3abl4d5outdo3natdom5izdo5lor4dlessu4bero3dles_at3alou3ble_d4is3tdirt5idi5niz3dine_at5ech5di3endi4cam1d4i3ad3ge4tud5estdev3ilde3strud3iedud3iesdes3tide2s5oat3egovis3itde4nardemor5at3en_uen4teuer4ilde5milat3eraugh3en3demicater5nuil5izdeli4ede5comde4cildecan4de4bonv3io4rdeb5it4dativ2d3a4bat3estu5laticu4tie5ulcheul3dercuss4icu5riaath5em3cultua5thenul3ingul5ishul4lar4vi4naul4liscu5ityctim3ic4ticuuls5esc5tantultra3ct5angcros4ecrop5ocro4pl5critiath5omum4blycre3at5vilitumor5oat5i5b5crat_cras5tcoro3ncop3iccom5ercol3orun5ishco3inc5clareat3ituunt3abat5ropun4tescit3iz4cisti4cista4cipicc5ing_cin3em3cinatuper5s5videsup3ingci2a5b5chini5videdupt5ib5vide_at4tag4ch1inch3ersch3er_ch5ene3chemiche5loure5atur4fercheap3vi5aliat3uravet3er4ch3abc5e4taau5sib3cessives4tece5ram2cen4e4cedenccou3turs5erur5tesur3theaut5enur4tiecav5al4cativave4nover3thcar5omca5percan4tycan3izcan5iscan4icus4lin3versecal4laver3ieca3latca5dencab3in3butiobuss4ebus5iebunt4iv4eresuten4i4u1t2iv3erenu3tineut3ingv4erelbroth35u5tizbound34b1orabon5at5vere_bom4bibol3icblun4t5blespblath5av3erav5enuebi3ogrbi5netven3om2v1a4bvac5ilbi3lizbet5izbe5strva5liebe5nigbbi4nabas4siva5nizbari4aav5ernbarbi5av5eryvel3liazi4eravi4er",
          7: "_dri5v4ban5dagvar5iedbina5r43bi3tio3bit5ua_ad4derution5auti5lizver5encbuf4ferus5terevermi4ncall5incast5ercas5tigccompa5z3o1phros5itiv5chanicuri4fico5stati5chine_y5che3dupport54v3iden5cific_un4ter_at5omiz4oscopiotele4g5craticu4m3ingv3i3liz4c3retaul4li4bcul4tiscur5a4b4c5utiva5ternauiv4er_del5i5qdem5ic_de4monsdenti5fdern5izdi4latou4b5ingdrag5on5drupliuar5ant5a5si4tec5essawo4k1enec5ifiee4compear5inate4f3eretro5phewide5sp5triciatri5cesefor5ese4fuse_oth5esiar5dinear4chantra5ventrac4tetrac4itar5ativa5ratioel5ativor5est_ar5adisel5ebraton4alie4l5ic_wea5rieel5igibe4l3ingto5cratem5igraem3i3niemoni5oench4erwave1g4a4pillavoice1ption5eewill5inent5age4enthesvaude3vtill5inep5recaep5ti5bva6guer4erati_tho5rizthor5it5thodicer5ence5ternitteri5zater5iesten4tage4sage_e4sagese4sert_an5est_e4sertse4servaes5idenes5ignaesis4tees5piraes4si4btal4lisestruc5e5titioounc5erxe4cutota5bleset5itiva4m5atoa4matis5stratu4f3ical5a5lyst4ficatefill5instern5isspend4gani5zasqual4la4lenti4g3o3nas5ophiz5sophicxpecto55graph_or5angeuri4al_4graphy4gress_smol5d4hang5erh5a5nizharp5enhar5terhel4lishith5erhro5niziam5eteia4tricic4t3uascour5au2r1al_5scin4dover4nescan4t55sa3tiou5do3ny_ven4de_under5ty2p5al_anti5sylla5bliner4arturn3ari5nite_5initioinsur5aion4eryiphras4_tim5o5_ten5an_sta5blrtroph4_se5rieiq3ui3t5i5r2izis5itiviso5mer4istral5i5ticki2t5o5mtsch3ie_re5mittro3fiti4v3er_i4vers_ros5per_pe5titiv3o3ro_ped5alro5n4is_or5ato4jestierom5ete_muta5bk5iness4latelitr4ial__mist5i_me5terr4ming_lev4er__mar5tilev4eralev4ers_mag5a5liar5iz5ligaterit5ers_lat5errit5er_r5ited__im5pinri3ta3blink5er_hon5ey5litica_hero5ior5aliz_hand5irip5lic_gen3t4tolo2gylloqui5_con5grt1li2erbad5ger4operag_eu4lertho3donter2ic__ar4tie_ge4ome_ge5ot1_he3mo1_he3p6a_he3roe_in5u2tpara5bl5tar2rht1a1mintalk1a5ta3gon_par5age_aster5_ne6o3f_noe1thstyl1is_poly1s5pathic_pre1ampa4tricl3o3niz_sem4ic_semid6_semip4_semir45ommend_semiv4lea4s1a_spin1oom5etryspher1o_to6poglo4ratospe3cio3s2paceso2lute_we2b1l_re1e4ca5bolicom5erseaf6fishside5swanal6ysano5a2cside5stl5ties_5lumniasid2ed_anti1reshoe1stscy4th1s4chitzsales5wsales3cat6tes_augh4tlau5li5fom5atizol5ogizo5litiorev5olure5vertre5versbi5d2ifbil2lab_earth5pera5blro1tronro3meshblan2d1blin2d1blon2d2bor1no5ro1bot1re4ti4zr5le5quperi5stper4malbut2ed_but4tedcad5e1moist5enre5stalress5ibchie5vocig3a3roint5er4matizariv1o1lcous2ticri3tie5phisti_be5stoog5ativo2g5a5rr3a3digm4b3ingre4posir4en4tade4als_od5uctsquasis6quasir6re5fer_p5trol3rec5olldic1aiddif5fra3pseu2dr5ebrat5metric2d1lead2d1li2epro2g1epre1neuod5uct_octor5apoin3came5triem5i5liepli5narpara3memin5glim5inglypi4grappal6matmis4er_m5istryeo3graporth1riop1ism__but4tio3normaonom1icfeb1ruafermi1o_de4moio5a5lesodit1icodel3lirb5ing_gen2cy_n4t3ingmo5lestration4get2ic_4g1lishobli2g1mon4ismnsta5blmon4istg2n1or_nov3el3ns5ceivno1vembmpa5rabno4rarymula5r4nom1a6lput4tinput4tedn5o5miz_cam4penag5er_nge5nesh2t1eoun1dieck2ne1skiifac1etncour5ane3backmono1s6mono3chmol1e5cpref5ac3militapre5tenith5i2lnge4n4end5est__capa5bje1re1mma1la1ply5styr1kovian_car5olprin4t3lo2ges_l2l3ishprof5it1s2tamp",
          8: "lead6er_url5ing_ces5si5bch5a5nis1le1noidlith1o5g_chill5ilar5ce1nym5e5trych5inessation5arload4ed_load6er_la4c3i5elth5i2lyneg5ativ1lunk3erwrit6er_wrap3arotrav5es51ke6linga5rameteman3u1scmar1gin1ap5illar5tisticamedio6c1me3gran3i1tesima3mi3da5bves1titemil2l1agv1er1eigmi6n3is_1verely_e4q3ui3s5tabolizg5rapher5graphicmo5e2lasinfra1s2mon4ey1lim3ped3amo4no1enab5o5liz_cor5nermoth4et2m1ou3sinm5shack2ppo5sitemul2ti5uab5it5abimenta5rignit1ernato5mizhypo1thani5ficatuad1ratu4n5i4an_ho6r1ic_ua3drati5nologishite3sidin5dling_trib5utin5glingnom5e1non1o1mistmpos5itenon1i4so_re5stattro1p2istrof4ic_g2norespgnet1ism5glo5binlem5aticflow2er_fla1g6elntrol5lifit5ted_treach1etra1versl5i5ticso3mecha6_for5mer_de5rivati2n3o1me3spac6i2t3i4an_thy4l1antho1k2er_eq5ui5to4s3phertha4l1amt3ess2es3ter1geiou3ba3dotele1r6ooxi6d1iceli2t1isonspir5apar4a1leed1ulingea4n3iesoc5ratiztch3i1er_kil2n3ipi2c1a3dpli2c1abt6ap6athdrom3e5d_le6icesdrif2t1a_me4ga1l1prema3cdren1a5lpres2plipro2cess_met4ala3do5word1syth3i2_non1e2m_post1ampto3mat4rec5ompepu5bes5cstrib5utqu6a3si31stor1ab_sem6is4star3tliqui3v4arr1abolic_sph6in1de5clar12d3aloneradi1o6gs3qui3tosports3wsports3cra5n2hascro5e2cor3bin1gespokes5wspi2c1il_te3legrcroc1o1d_un3at5t_dictio5cat1a1s2buss4ingbus6i2esbus6i2erbo2t1u1lro5e2las1s2pacinb1i3tivema5rine_r3pau5li_un5err5r5ev5er__vi2c3arback2er_ma5chinesi5resid5losophyan3ti1n2sca6p1ersca2t1olar2rangesep3temb1sci2uttse3mes1tar3che5tsem1a1ph",
          9: "re4t1ribuuto5maticl3chil6d1a4pe5able1lec3ta6bas5ymptotyes5ter1yl5mo3nell5losophizlo1bot1o1c5laratioba6r1onierse1rad1iro5epide1co6ph1o3nscrap4er_rec5t6angre2c3i1prlai6n3ess1lum5bia_3lyg1a1miec5ificatef5i5nites2s3i4an_1ki5neticjapan1e2smed3i3cinirre6v3ocde2c5linao3les3termil5li5listrat1a1gquain2t1eep5etitiostu1pi4d1v1oir5du1su2per1e6_mi1s4ers3di1methy_mim5i2c1i5nitely_5maph1ro15moc1ra1tmoro6n5isdu1op1o1l_ko6r1te1n3ar4chs_phi2l3ant_ga4s1om1teach4er_parag6ra4o6v3i4an_oth3e1o1sn3ch2es1to5tes3toro5test1eror5tively5nop5o5liha2p3ar5rttrib1ut1_eth1y6l1e2r3i4an_5nop1oly_graph5er_5eu2clid1o1lo3n4omtrai3tor1_ratio5na5mocratiz_rav5en1o",
          10: "se1mi6t5ic3tro1le1um5sa3par5iloli3gop1o1am1en3ta5bath3er1o1s3slova1kia3s2og1a1myo3no2t1o3nc2tro3me6c1cu2r1ance5noc3er1osth1o5gen1ih3i5pel1a4nfi6n3ites_ever5si5bs2s1a3chu1d1ri3pleg5_ta5pes1trproc3i3ty_s5sign5a3b3rab1o1loiitin5er5arwaste3w6a2mi1n2ut1erde3fin3itiquin5tes5svi1vip3a3r",
          11: "pseu3d6o3f2s2t1ant5shimi1n2ut1estpseu3d6o3d25tab1o1lismpo3lyph1onophi5lat1e3ltravers3a3bschro1ding12g1o4n3i1zat1ro1pol3it3trop1o5lis3trop1o5lesle3g6en2dreeth1y6l1eneor4tho3ni4t",
          12: "3ra4m5e1triz1e6p3i3neph1"
        }
      };
    }
  });

  // node_modules/tex-linebreak/dist/lib.js
  var require_lib = __commonJS({
    "node_modules/tex-linebreak/dist/lib.js"(exports, module) {
      !(function(t, e) {
        "object" == typeof exports && "object" == typeof module ? module.exports = e() : "function" == typeof define && define.amd ? define([], e) : "object" == typeof exports ? exports.texLineBreak_lib = e() : t.texLineBreak_lib = e();
      })("undefined" != typeof self ? self : exports, (() => {
        return t = { 381: (t2) => {
          function e2(t3) {
            var e3 = [], u = 0;
            if (this.trie = this.createTrie(t3.patterns), this.leftMin = t3.leftmin, this.rightMin = t3.rightmin, this.exceptions = {}, t3.exceptions) for (e3 = t3.exceptions.split(/,\s?/g); u < e3.length; u += 1) this.exceptions[e3[u].replace(/\u2027/g, "").toLowerCase()] = new RegExp("(" + e3[u].split("\u2027").join(")(") + ")", "i");
          }
          e2.TrieNode, e2.prototype.createTrie = function(t3) {
            var e3, u = 0, n = 0, o = 0, i = 0, s = null, r = null, a = null, l = null, c = { _points: [] };
            for (u in t3) if (t3.hasOwnProperty(u)) for (e3 = t3[u].match(new RegExp(".{1," + +u + "}", "g")), n = 0; n < e3.length; n += 1) {
              for (s = e3[n].replace(/[0-9]/g, "").split(""), r = e3[n].split(/\D/), l = c, o = 0; o < s.length; o += 1) l[a = s[o].charCodeAt(0)] || (l[a] = {}), l = l[a];
              for (l._points = [], i = 0; i < r.length; i += 1) l._points[i] = r[i] || 0;
            }
            return c;
          }, e2.prototype.hyphenateText = function(t3, e3) {
            e3 = e3 || 4;
            for (var u = t3.split(/([a-zA-Z0-9_\u0027\u00AD\u00DF-\u00EA\u00EB\u00EC-\u00EF\u00F1-\u00F6\u00F8-\u00FD\u0101\u0103\u0105\u0107\u0109\u010D\u010F\u0111\u0113\u0117\u0119\u011B\u011D\u011F\u0123\u0125\u012B\u012F\u0131\u0135\u0137\u013C\u013E\u0142\u0144\u0146\u0148\u0151\u0153\u0155\u0159\u015B\u015D\u015F\u0161\u0165\u016B\u016D\u016F\u0171\u0173\u017A\u017C\u017E\u017F\u0219\u021B\u02BC\u0390\u03AC-\u03CE\u03F2\u0401\u0410-\u044F\u0451\u0454\u0456\u0457\u045E\u0491\u0531-\u0556\u0561-\u0587\u0902\u0903\u0905-\u090B\u090E-\u0910\u0912\u0914-\u0928\u092A-\u0939\u093E-\u0943\u0946-\u0948\u094A-\u094D\u0982\u0983\u0985-\u098B\u098F\u0990\u0994-\u09A8\u09AA-\u09B0\u09B2\u09B6-\u09B9\u09BE-\u09C3\u09C7\u09C8\u09CB-\u09CD\u09D7\u0A02\u0A03\u0A05-\u0A0A\u0A0F\u0A10\u0A14-\u0A28\u0A2A-\u0A30\u0A32\u0A33\u0A35\u0A36\u0A38\u0A39\u0A3E-\u0A42\u0A47\u0A48\u0A4B-\u0A4D\u0A82\u0A83\u0A85-\u0A8B\u0A8F\u0A90\u0A94-\u0AA8\u0AAA-\u0AB0\u0AB2\u0AB3\u0AB5-\u0AB9\u0ABE-\u0AC3\u0AC7\u0AC8\u0ACB-\u0ACD\u0B02\u0B03\u0B05-\u0B0B\u0B0F\u0B10\u0B14-\u0B28\u0B2A-\u0B30\u0B32\u0B33\u0B35-\u0B39\u0B3E-\u0B43\u0B47\u0B48\u0B4B-\u0B4D\u0B57\u0B82\u0B83\u0B85-\u0B8A\u0B8E-\u0B90\u0B92-\u0B95\u0B99\u0B9A\u0B9C\u0B9E\u0B9F\u0BA3\u0BA4\u0BA8-\u0BAA\u0BAE-\u0BB5\u0BB7-\u0BB9\u0BBE-\u0BC2\u0BC6-\u0BC8\u0BCA-\u0BCD\u0BD7\u0C02\u0C03\u0C05-\u0C0B\u0C0E-\u0C10\u0C12\u0C14-\u0C28\u0C2A-\u0C33\u0C35-\u0C39\u0C3E-\u0C43\u0C46-\u0C48\u0C4A-\u0C4D\u0C82\u0C83\u0C85-\u0C8B\u0C8E-\u0C90\u0C92\u0C94-\u0CA8\u0CAA-\u0CB3\u0CB5-\u0CB9\u0CBE-\u0CC3\u0CC6-\u0CC8\u0CCA-\u0CCD\u0D02\u0D03\u0D05-\u0D0C\u0D0E-\u0D10\u0D12-\u0D28\u0D2A-\u0D39\u0D3E-\u0D43\u0D46-\u0D48\u0D4A-\u0D4D\u0D57\u0D60\u0D61\u0D7A-\u0D7F\u1F00-\u1F07\u1F10-\u1F15\u1F20-\u1F27\u1F30-\u1F37\u1F40-\u1F45\u1F50-\u1F57\u1F60-\u1F67\u1F70-\u1F7D\u1F80-\u1F87\u1F90-\u1F97\u1FA0-\u1FA7\u1FB2-\u1FB4\u1FB6\u1FB7\u1FBD\u1FBF\u1FC2-\u1FC4\u1FC6\u1FC7\u1FD2\u1FD3\u1FD6\u1FD7\u1FE2-\u1FE7\u1FF2-\u1FF4\u1FF6\u1FF7\u200D\u2019]+)/gi), n = 0; n < u.length; n += 1) -1 !== u[n].indexOf("/") ? 0 === n || n === u.length - 1 || /\s+\/|\/\s+/.test(u[n]) || (u[n] += "\u200B") : u[n].length > e3 && (u[n] = this.hyphenate(u[n]).join("\xAD"));
            return u.join("");
          }, e2.prototype.hyphenate = function(t3) {
            var e3, u, n, o, i, s, r, a, l, c = [], h = [], d = t3.toLowerCase(), p = Math.max, f = this.trie, y = [""];
            if (this.exceptions.hasOwnProperty(d)) return t3.match(this.exceptions[d]).slice(1);
            if (-1 !== t3.indexOf("\xAD")) return [t3];
            for (e3 = (t3 = "_" + t3 + "_").toLowerCase().split(""), u = t3.split(""), r = e3.length, n = 0; n < r; n += 1) h[n] = 0, c[n] = e3[n].charCodeAt(0);
            for (n = 0; n < r; n += 1) for (s = f, o = n; o < r && (s = s[c[o]]); o += 1) if (a = s._points) for (i = 0, l = a.length; i < l; i += 1) h[n + i] = p(h[n + i], a[i]);
            for (n = 1; n < r - 1; n += 1) n > this.leftMin && n < r - this.rightMin && h[n] % 2 ? y.push(u[n]) : y[y.length - 1] += u[n];
            return y;
          }, t2.exports = e2;
        }, 673: (t2, e2, u) => {
          "use strict";
          Object.defineProperty(e2, "__esModule", { value: true }), e2.layoutText = e2.layoutItemsFromString = void 0;
          const n = u(924);
          function o(t3, e3, u2) {
            const o2 = [], i = t3.split(/(\s+)/).filter(((t4) => t4.length > 0)), s = e3(" "), r = e3("-"), a = Math.max(0, s - 2);
            return i.forEach(((t4) => {
              if (/\s/.test(t4.charAt(0))) {
                const e4 = { type: "glue", width: s, shrink: a, stretch: 1.5 * s, text: t4 };
                o2.push(e4);
              } else if (u2) {
                const n2 = u2(t4);
                n2.forEach(((t5, u3) => {
                  const i2 = { type: "box", width: e3(t5), text: t5 };
                  if (o2.push(i2), u3 < n2.length - 1) {
                    const t6 = { type: "penalty", width: r, cost: 10, flagged: true };
                    o2.push(t6);
                  }
                }));
              } else {
                const u3 = { type: "box", width: e3(t4), text: t4 };
                o2.push(u3);
              }
            })), o2.push({ type: "glue", width: 0, stretch: n.MAX_COST, shrink: 0, text: "" }), o2.push((0, n.forcedBreak)()), o2;
          }
          e2.layoutItemsFromString = o, e2.layoutText = function(t3, e3, u2, i) {
            let s, r, a;
            try {
              s = o(t3, u2), r = (0, n.breakLines)(s, e3, { maxAdjustmentRatio: 1 }), a = (0, n.positionItems)(s, e3, r);
            } catch (l) {
              if (!(l instanceof n.MaxAdjustmentExceededError)) throw l;
              s = o(t3, u2, i), r = (0, n.breakLines)(s, e3), a = (0, n.positionItems)(s, e3, r);
            }
            return { items: s, breakpoints: r, positions: a };
          };
        }, 795: function(t2, e2, u) {
          "use strict";
          var n = this && this.__importDefault || function(t3) {
            return t3 && t3.__esModule ? t3 : { default: t3 };
          };
          Object.defineProperty(e2, "__esModule", { value: true }), e2.justifyContent = e2.unjustifyContent = void 0;
          const o = u(924), i = u(976), s = n(u(612)), r = "insertedByTexLinebreak";
          function a(t3, e3, u2, n2, i2 = true) {
            if (Array.from(e3.childNodes).forEach(((e4) => {
              e4 instanceof Text ? (function(t4, e5, u3, n3) {
                const o2 = e5.nodeValue, i3 = e5.parentNode, s2 = u3(i3, " "), r2 = Math.max(0, s2 - 3), a2 = u3(i3, "-"), l2 = o2.split(/(\s+)/).filter(((t5) => t5.length > 0));
                let c2 = 0;
                l2.forEach(((o3) => {
                  if (/\s/.test(o3.charAt(0))) {
                    const u4 = { type: "glue", width: s2, shrink: r2, stretch: s2, node: e5, start: c2, end: c2 + o3.length };
                    return t4.push(u4), void (c2 += o3.length);
                  }
                  if (n3) {
                    const s3 = n3(o3);
                    s3.forEach(((n4, o4) => {
                      const r3 = { type: "box", width: u3(i3, n4), node: e5, start: c2, end: c2 + n4.length };
                      if (c2 += n4.length, t4.push(r3), o4 < s3.length - 1) {
                        const u4 = { type: "penalty", width: a2, cost: 10, flagged: true, node: e5, start: c2, end: c2 };
                        t4.push(u4);
                      }
                    }));
                  } else {
                    const n4 = { type: "box", width: u3(i3, o3), node: e5, start: c2, end: c2 + o3.length };
                    c2 += o3.length, t4.push(n4);
                  }
                }));
              })(t3, e4, u2, n2) : e4 instanceof Element && (function(t4, e5, u3, n3) {
                const { display: o2, width: i3, paddingLeft: s2, paddingRight: r2, marginLeft: l2, marginRight: c2, borderLeftWidth: h2, borderRightWidth: d2 } = getComputedStyle(e5);
                if ("inline" === o2) {
                  const o3 = parseFloat(l2) + parseFloat(h2) + parseFloat(s2);
                  o3 > 0 && t4.push({ type: "box", width: o3, node: e5, start: 0, end: 0 }), a(t4, e5, u3, n3, false);
                  const i4 = parseFloat(c2) + parseFloat(d2) + parseFloat(r2);
                  if (i4 > 0) {
                    const u4 = e5.childNodes.length;
                    t4.push({ type: "box", width: i4, node: e5, start: u4, end: u4 });
                  }
                } else t4.push({ type: "box", width: parseFloat(i3), node: e5, start: 0, end: 1 });
              })(t3, e4, u2, n2);
            })), i2) {
              const u3 = e3.childNodes.length;
              t3.push({ type: "glue", width: 0, shrink: 0, stretch: 1e3, node: e3, start: u3, end: u3 }), t3.push(Object.assign(Object.assign({}, (0, o.forcedBreak)()), { node: e3, start: u3, end: u3 }));
            }
          }
          function l(t3) {
            t3[r] = true;
          }
          function c(t3) {
            return t3.hasOwnProperty(r);
          }
          function h(t3) {
            const e3 = [];
            for (let u2 = 0; u2 < t3.childNodes.length; u2++) {
              const n2 = t3.childNodes[u2];
              c(n2) && e3.push(n2), n2.childNodes.length > 0 && e3.push(...h(n2));
            }
            return e3;
          }
          function d(t3) {
            return t3 instanceof Text || t3 instanceof Element && "inline" === getComputedStyle(t3).display;
          }
          function p(t3) {
            const e3 = h(t3);
            for (let t4 of e3) {
              const e4 = t4.parentNode;
              Array.from(t4.childNodes).forEach(((u2) => {
                e4.insertBefore(u2, t4);
              })), e4.removeChild(t4);
            }
            t3.normalize();
          }
          e2.unjustifyContent = p, e2.justifyContent = function(t3, e3) {
            Array.isArray(t3) || (t3 = [t3]), t3.forEach(((t4) => {
              p(t4);
            }));
            const u2 = new s.default(), n2 = u2.measure.bind(u2), r2 = [];
            t3.forEach(((t4) => {
              const u3 = (function(t5) {
                const { width: e4, boxSizing: u4, paddingLeft: n3, paddingRight: o2 } = getComputedStyle(t5);
                let i3 = parseFloat(e4);
                return "border-box" === u4 && (i3 -= parseFloat(n3), i3 -= parseFloat(o2)), i3;
              })(t4);
              let i2, s2 = [];
              a(s2, t4, n2);
              try {
                i2 = (0, o.breakLines)(s2, u3, { maxAdjustmentRatio: 2 });
              } catch (r3) {
                if (!(r3 instanceof o.MaxAdjustmentExceededError)) throw r3;
                s2 = [], a(s2, t4, n2, e3), i2 = (0, o.breakLines)(s2, u3);
              }
              r2.push({ el: t4, items: s2, breakpoints: i2, lineWidth: u3 });
            })), r2.forEach((({ el: t4, items: e4, breakpoints: u3, lineWidth: n3 }) => {
              const [o2, s2] = (function(t5, e5) {
                const u4 = [], n4 = [];
                for (let o3 = 0; o3 < e5.length - 1; o3++) {
                  let i2 = 0, s3 = 0;
                  const r4 = 0 === o3 ? e5[o3] : e5[o3] + 1;
                  for (let u5 = r4; u5 <= e5[o3 + 1]; u5++) {
                    const n5 = t5[u5];
                    "box" === n5.type ? i2 += n5.width : "glue" === n5.type && u5 !== r4 && u5 !== e5[o3 + 1] ? (i2 += n5.width, ++s3) : "penalty" === n5.type && u5 === e5[o3 + 1] && (i2 += n5.width);
                  }
                  u4.push(i2), n4.push(s3);
                }
                return [u4, n4];
              })(e4, u3), r3 = [], a2 = [];
              for (let n4 = 1; n4 < u3.length; n4++) {
                const o3 = e4[u3[n4 - 1]], i2 = e4[u3[n4]], s3 = document.createRange();
                n4 > 1 ? s3.setStart(o3.node, o3.end) : s3.setStart(t4, 0), s3.setEnd(i2.node, i2.start), a2.push(s3), r3.push("penalty" === i2.type && i2.flagged);
              }
              t4.style.whiteSpace = "nowrap", a2.forEach(((t5, e5) => {
                if (0 === e5) return;
                const u4 = document.createElement("br");
                l(u4), t5.insertNode(u4), t5.setStart(u4.nextSibling, 0);
              })), a2.forEach(((t5, e5) => {
                const u4 = (n3 - o2[e5]) / s2[e5];
                if (e5 === a2.length - 1 && u4 >= 0) return;
                const c2 = (function(t6, e6) {
                  const u5 = (0, i.textNodesInRange)(t6, d);
                  for (let t7 of u5) {
                    const u6 = document.createElement("span");
                    l(u6), u6.style.wordSpacing = `${e6}px`, t7.parentNode.replaceChild(u6, t7), u6.appendChild(t7);
                  }
                  return u5;
                })(t5, u4);
                if (r3[e5] && c2.length > 0) {
                  const t6 = c2[c2.length - 1], e6 = document.createTextNode("-");
                  l(e6), t6.parentNode.appendChild(e6);
                }
              }));
            }));
          };
        }, 204: function(t2, e2, u) {
          "use strict";
          var n = this && this.__importDefault || function(t3) {
            return t3 && t3.__esModule ? t3 : { default: t3 };
          };
          Object.defineProperty(e2, "__esModule", { value: true }), e2.createHyphenator = void 0;
          const o = n(u(381));
          e2.createHyphenator = function(t3) {
            const e3 = new o.default(t3);
            return (t4) => e3.hyphenate(t4);
          };
        }, 156: function(t2, e2, u) {
          "use strict";
          var n = this && this.__createBinding || (Object.create ? function(t3, e3, u2, n2) {
            void 0 === n2 && (n2 = u2);
            var o2 = Object.getOwnPropertyDescriptor(e3, u2);
            o2 && !("get" in o2 ? !e3.__esModule : o2.writable || o2.configurable) || (o2 = { enumerable: true, get: function() {
              return e3[u2];
            } }), Object.defineProperty(t3, n2, o2);
          } : function(t3, e3, u2, n2) {
            void 0 === n2 && (n2 = u2), t3[n2] = e3[u2];
          }), o = this && this.__exportStar || function(t3, e3) {
            for (var u2 in t3) "default" === u2 || Object.prototype.hasOwnProperty.call(e3, u2) || n(e3, t3, u2);
          };
          Object.defineProperty(e2, "__esModule", { value: true }), o(u(924), e2), o(u(673), e2), o(u(795), e2), o(u(204), e2);
        }, 924: (t2, e2) => {
          "use strict";
          function u(t3) {
            return "penalty" === t3.type && t3.cost <= e2.MIN_COST;
          }
          Object.defineProperty(e2, "__esModule", { value: true }), e2.forcedBreak = e2.positionItems = e2.adjustmentRatios = e2.breakLines = e2.MaxAdjustmentExceededError = e2.MAX_COST = e2.MIN_COST = void 0, e2.MIN_COST = -1e3, e2.MAX_COST = 1e3;
          const n = { maxAdjustmentRatio: null, initialMaxAdjustmentRatio: 1, doubleHyphenPenalty: 0, adjacentLooseTightPenalty: 0 };
          class o extends Error {
          }
          function i(t3, e3, u2) {
            const n2 = [];
            for (let i2 = 0; i2 < u2.length - 1; i2++) {
              let s = (o2 = i2, Array.isArray(e3) ? e3[o2] : e3), r = 0, a = 0, l = 0;
              const c = 0 === i2 ? u2[i2] : u2[i2] + 1;
              for (let e4 = c; e4 <= u2[i2 + 1]; e4++) {
                const n3 = t3[e4];
                "box" === n3.type ? r += n3.width : "glue" === n3.type && e4 !== c && e4 !== u2[i2 + 1] ? (r += n3.width, a += n3.shrink, l += n3.stretch) : "penalty" === n3.type && e4 === u2[i2 + 1] && (r += n3.width);
              }
              let h;
              h = r < s ? (s - r) / l : (s - r) / a, n2.push(h);
            }
            var o2;
            return n2;
          }
          e2.MaxAdjustmentExceededError = o, e2.breakLines = function t3(i2, s, r = {}) {
            if (0 === i2.length) return [];
            const a = i2.some(((t4) => "box" === t4.type || "penalty" === t4.type ? t4.width < 0 : t4.width < 0 || t4.stretch < 0 || t4.shrink < 0)), l = Object.assign(Object.assign({}, n), r), c = Math.min(l.initialMaxAdjustmentRatio, null !== l.maxAdjustmentRatio ? l.maxAdjustmentRatio : 1 / 0), h = /* @__PURE__ */ new Set();
            h.add({ index: 0, line: 0, fitness: 0, totalWidth: 0, totalStretch: 0, totalShrink: 0, totalDemerits: 0, prev: null });
            let d = 0, p = 0, f = 0, y = 1 / 0;
            for (let n2 = 0; n2 < i2.length; n2++) {
              const g2 = i2[n2];
              let A2 = false;
              if ("box" === g2.type ? d += g2.width : "glue" === g2.type ? (A2 = n2 > 0 && "box" === i2[n2 - 1].type, A2 || (d += g2.width, f += g2.shrink, p += g2.stretch)) : "penalty" === g2.type && (A2 = g2.cost < e2.MAX_COST), !A2) continue;
              let C2 = null;
              const B = [];
              if (h.forEach(((t4) => {
                let o2 = 0;
                const r2 = f - t4.totalShrink, A3 = p - t4.totalStretch, x = (F = t4.line, Array.isArray(s) ? s[F] : s);
                var F;
                let m = d - t4.totalWidth;
                if ("penalty" === g2.type && (m += g2.width), o2 = m < x ? (x - m) / A3 : (x - m) / r2, o2 > c && (y = Math.min(o2, y)), (!a && o2 < -1 || u(g2)) && (h.delete(t4), C2 = t4), o2 >= -1 && o2 <= c) {
                  let u2;
                  const s2 = 100 * Math.abs(o2) ** 3, r3 = "penalty" === g2.type ? g2.cost : 0;
                  u2 = r3 >= 0 ? (1 + s2 + r3) ** 2 : r3 > e2.MIN_COST ? (1 + s2) ** 2 - r3 ** 2 : (1 + s2) ** 2;
                  let a2 = 0;
                  const c2 = i2[t4.index];
                  let h2;
                  "penalty" === g2.type && "penalty" === c2.type && g2.flagged && c2.flagged && (a2 = l.doubleHyphenPenalty), u2 += a2, h2 = o2 < -0.5 ? 0 : o2 < 0.5 ? 1 : o2 < 1 ? 2 : 3, t4.index > 0 && Math.abs(h2 - t4.fitness) > 1 && (u2 += l.adjacentLooseTightPenalty);
                  let y2 = 0, A4 = 0, C3 = 0;
                  for (let t5 = n2; t5 < i2.length; t5++) {
                    const u3 = i2[t5];
                    if ("box" === u3.type) break;
                    if ("penalty" === u3.type && u3.cost >= e2.MAX_COST) break;
                    y2 += u3.width, "glue" === u3.type && (A4 += u3.shrink, C3 += u3.stretch);
                  }
                  const x2 = { index: n2, line: t4.line + 1, fitness: h2, totalWidth: d + y2, totalShrink: f + A4, totalStretch: p + C3, totalDemerits: t4.totalDemerits + u2, prev: t4 };
                  B.push(x2);
                }
              })), B.length > 0) {
                let t4 = B[0];
                for (let e3 of B) e3.totalDemerits < t4.totalDemerits && (t4 = e3);
                h.add(t4);
              }
              if (0 === h.size) {
                if (isFinite(y)) {
                  if (l.maxAdjustmentRatio === c) throw new o();
                  return t3(i2, s, Object.assign(Object.assign({}, r), { initialMaxAdjustmentRatio: 2 * y }));
                }
                h.add({ index: n2, line: C2.line + 1, fitness: 1, totalWidth: d, totalShrink: f, totalStretch: p, totalDemerits: C2.totalDemerits + 1e3, prev: C2 });
              }
              "glue" === g2.type && (d += g2.width, p += g2.stretch, f += g2.shrink);
            }
            let g = null;
            h.forEach(((t4) => {
              (!g || t4.totalDemerits < g.totalDemerits) && (g = t4);
            }));
            const A = [];
            let C = g;
            for (; C; ) A.push(C.index), C = C.prev;
            return A.reverse(), A;
          }, e2.adjustmentRatios = i, e2.positionItems = function(t3, e3, u2, n2 = {}) {
            const o2 = i(t3, e3, u2), s = [];
            for (let e4 = 0; e4 < u2.length - 1; e4++) {
              const i2 = Math.max(o2[e4], -1);
              let r = 0;
              const a = 0 === e4 ? u2[e4] : u2[e4] + 1;
              for (let o3 = a; o3 <= u2[e4 + 1]; o3++) {
                const l = t3[o3];
                if ("box" === l.type) s.push({ item: o3, line: e4, xOffset: r, width: l.width }), r += l.width;
                else if ("glue" === l.type && o3 !== a && o3 !== u2[e4 + 1]) {
                  let t4;
                  t4 = i2 < 0 ? l.width + i2 * l.shrink : l.width + i2 * l.stretch, n2.includeGlue && s.push({ item: o3, line: e4, xOffset: r, width: t4 }), r += t4;
                } else "penalty" === l.type && o3 === u2[e4 + 1] && l.width > 0 && s.push({ item: o3, line: e4, xOffset: r, width: l.width });
              }
            }
            return s;
          }, e2.forcedBreak = function() {
            return { type: "penalty", cost: e2.MIN_COST, width: 0, flagged: false };
          };
        }, 612: (t2, e2) => {
          "use strict";
          Object.defineProperty(e2, "__esModule", { value: true });
          class u {
            constructor() {
              this._fonts = /* @__PURE__ */ new Map(), this._textWidths = /* @__PURE__ */ new Map();
            }
            putFont(t3, e3) {
              this._fonts.set(t3, e3);
            }
            cssFontForElement(t3) {
              return this._fonts.get(t3);
            }
            putWidth(t3, e3, u2) {
              let n2 = this._textWidths.get(t3);
              n2 || (n2 = /* @__PURE__ */ new Map(), this._textWidths.set(t3, n2)), n2.set(e3, u2);
            }
            getWidth(t3, e3) {
              const u2 = this._textWidths.get(t3);
              return u2 ? u2.get(e3) : null;
            }
          }
          let n;
          e2.default = class {
            constructor() {
              this._cache = new u();
            }
            measure(t3, e3) {
              let u2 = this._cache.cssFontForElement(t3);
              u2 || (u2 = (function(t4) {
                const e4 = getComputedStyle(t4);
                let u3 = e4.font;
                if (u3.length > 0) return u3;
                const { fontStyle: n2, fontVariant: o2, fontWeight: i, fontSize: s, fontFamily: r } = e4;
                return u3 = `${n2} ${o2} ${i} ${s} ${r}`, u3;
              })(t3), this._cache.putFont(t3, u2));
              let o = this._cache.getWidth(u2, e3);
              return o || (o = (function(t4, e4) {
                if (!n) {
                  const t5 = document.createElement("canvas");
                  n = t5.getContext("2d");
                }
                return n.font = t4, n.measureText(e4).width;
              })(u2, e3), this._cache.putWidth(u2, e3, o)), o;
            }
          };
        }, 976: (t2, e2) => {
          "use strict";
          Object.defineProperty(e2, "__esModule", { value: true }), e2.textNodesInRange = void 0, e2.textNodesInRange = function(t3, e3) {
            const u = t3.commonAncestorContainer, n = u.ownerDocument.createTreeWalker(u, NodeFilter.SHOW_ALL, { acceptNode: (t4) => e3(t4) ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_REJECT }, false);
            let o = n.currentNode, i = [];
            for (; o; ) t3.intersectsNode(o) && o instanceof Text && i.push(o), o = n.nextNode();
            return i;
          };
        } }, e = {}, (function u(n) {
          var o = e[n];
          if (void 0 !== o) return o.exports;
          var i = e[n] = { exports: {} };
          return t[n].call(i.exports, i, i.exports, u), i.exports;
        })(156);
        var t, e;
      }));
    }
  });

  // tex-linebreak.ts
  var tex_linebreak_exports = {};
  __export(tex_linebreak_exports, {
    createHyphenator: () => import_tex_linebreak.createHyphenator,
    enUsPatterns: () => import_hyphenation.default,
    hyphenate: () => hyphenate,
    justifyAll: () => justifyAll,
    justifyContent: () => import_tex_linebreak.justifyContent
  });
  var import_hyphenation = __toESM(require_en_us());
  var import_tex_linebreak = __toESM(require_lib());
  var hyphenate = (0, import_tex_linebreak.createHyphenator)(import_hyphenation.default);
  function justifyAll() {
    const paragraphs = Array.from(document.querySelectorAll("p, li"));
    paragraphs.forEach((el) => el.classList.add("justified-text"));
    (0, import_tex_linebreak.justifyContent)(paragraphs, hyphenate);
  }
  window.addEventListener("DOMContentLoaded", () => {
    window.addEventListener("load", justifyAll);
    let resizeTimeout;
    window.addEventListener("resize", () => {
      clearTimeout(resizeTimeout);
      resizeTimeout = window.setTimeout(justifyAll, 150);
    });
  });
  return __toCommonJS(tex_linebreak_exports);
})();
