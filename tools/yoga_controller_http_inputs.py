"""Fixed locked HTTP bytes for one fresh reserved controller qualification."""
import hashlib
import json
import os
from pathlib import Path
import stat
import guard_native_seed_plan_reserved as kernel

SOURCE_ROOT=Path(__file__).resolve().parent.parent
CACHE=Path('/srv/fast-local/jess/state/codex/omux-bazel9-owner-coordinator-20261004/cache/repos/v1')
NAME='yoga-controller-http-inputs'
MAX_FILE=256*1024**2
MAX_TOTAL=512*1024**2
MODULE_SHA256='efef226341674d725c68a4eea426ba29cd91d06a60be20a4003ed7f09141a2ae'
LOCK_SHA256='5c25144a540f0d43c0b12eaf5720707cbaefc6cc6514e0fa740778bb1cc69ea1'
# Digests derive only from current MODULE, its locked BCR source metadata and
# locked HTTP extension attributes. No caller URL or mutable cache index is read.
# Required: lock metadata and directly declared module archives/patches.
# Optional: locked transitive/extension archives; if absent and actually needed,
# Bazel still refuses with downloads disabled. Presence never proves closure.
DECLARED=(
    ('002d62d9108f75bb807cd56245d45648f38275cb3a99dcd45dfb864c5d74cb96',True),
    ('004ba890363d05372a97248c37205ae64b6fa31047629cd2c0895a9d0c7779e8',True),
    ('00e501db01bbf4e3e1dd1595959092c2fadf2087b2852d3f553b5370f5633592',True),
    ('017cbfd2fdb9e6cc1d59be4449edb34bcaa2a269a5c00843d48b8f72ee044153',False),
    ('01b2e0ef893383a50dbeb13970fe7fa3be36ca3e83259e01649945b09d736985',False),
    ('028a084b65dcf8f4dc4f82f8778dbe65df133f234b316828a82e060d81bdce32',True),
    ('039de32d21b816b47bd42c778e0454217e9c9caac4a3cf8e15c7231ee3ddee4d',True),
    ('05d1933f0a5ba7d8d6296bb6d5018e7c94fa473ceb10cf198a92ccea19c27b53',False),
    ('05e3d6d30c099b6770e97da986c53bd31844d7f13d41412480ea265ac9e8079c',True),
    ('06367c5178e365ff9d9df48ab28e6b080c344a06f52cb01157df881739d2cb14',False),
    ('06c0334c9be61e6cef2c8c84a7800cef502063269a5af25ceb100b192453d4ab',True),
    ('07b389abc85fdbca459b69e2ec656ae5622873af3f845e1c9d80fe179f3effa0',True),
    ('088fbeb0b6a419005b89cf93fe62d9517c0a2b8bb56af3244af65ecfe37e7d5d',True),
    ('0a59d91fa1cb40cf068e9b0954434ce973500c7a2ea749f1e01af62cdab52d26',False),
    ('0d1caf0b8375942ce98ea944be754a18874041e4e0459401d925577624d3a54a',True),
    ('0daefc49732e227caa8bfa834d65dc52e8cc18a2faf80df25e8caea151a9413f',True),
    ('0db596f4563de7938de764cc8deeabec291f55e8ec15299718b93c4423e9796d',True),
    ('0e1ed4a98f26e718776bd64d053d02bb34d98572ccd03d6ba355112a1205706b',False),
    ('0e62471818affb9f0b26f128831d5c40b074d32e6dda5a0d3852847215a41ca4',True),
    ('0e8529ed7b323dad0775ff924d2ae5af7640b23553dfcd4d34344c7e7a867191',True),
    ('0e89367f1cb6d93a5a1afea4b55b11ea6b28f63f653b47154153677ca7d4afea',False),
    ('0eadc4395959969297cbcf31a249ff457f2f1d456228c67719480205aa306daa',True),
    ('0f3709e770aa0ea0fe0226e8025f13ab6fdf2894579f48393b68385107cbadb1',False),
    ('114775b816b38b6d0ca620450d6b02550c60ceedfdc8d9a229833b34a223dc42',True),
    ('14a225870ab4e91869652cfd69ef2028277fc1dc4910d65d353b62d6e0ae21f4',False),
    ('1639617eb1ede28d774d967a738b4a68b0accb40650beadb57c21846beab5efd',True),
    ('1692f77d1739bacf3f94337188b78583cf09bab7e420d2dc6c5605a4f86785a1',False),
    ('1843d7cd8a58369a444fc6000e7304425fba600ff641592161d9f15b179fb896',True),
    ('1849602c86cb60da8613d2de887f9566a6d354a6df6d7009f9d04a14402f9a84',True),
    ('185b5f3678d79528449a9de8d07893abc0167f46293712e498654cb7df1071f2',False),
    ('1a05d92974d0c122f5ccf09291442580317cdd859f07a8655f1db9a60374f9f8',True),
    ('1add3e7d93ff2e6998f9e118022c84d163917d912f5afafb3058e3d2f1545b5e',True),
    ('1be0ae2557ab3a72a57aeb31b29be347bcdc5d2b1eb1e70f39e3851a7e97041a',True),
    ('1c080cb389eba74c6868d8c4b9decdd8494bee6439cef026b87caf112405f3a1',False),
    ('1c0c09f5bdcf4b3f924720d2478a3711cb39f4977019ca5988685e5b7e18b3d2',True),
    ('1c4207dc858d6de0eecef30026793616bbf420c74aac27b6bad212534a730437',True),
    ('1c8cec495288dccd14fdae6e3f95f772c1c91857047a098fad772034264cc8cb',True),
    ('1cbe9df9f27e6b78d14ccbca43b6703a404ef79ef1c463de901d7f088d4e2026',False),
    ('1d440d262d0e08453fa0c4d8f699ba81609ed0e9a9a0f02cd10b3e7942e61e31',True),
    ('1de5b47721fce0af0dd453b3071228fdfc44bd18199826b3f0b03b423aae9f65',True),
    ('1e5b502e2e1a9e825eef74476a5a1ee524a92297085015a052510b09a1a09483',True),
    ('1f98ed015f7e744a745e0df6e898a7c5e83562d6b759dfd475c76456dda5ccea',True),
    ('20152b14d9a420afc15ace905c02fd6425ddceb084630f3f043b287adf0fcdbd',False),
    ('20228b92868bf5cfc41bda7afc8a8ba2a543201851de39d990ec957b513579c5',True),
    ('20ec05cd5e592055e214b2da8ccb283c7f2a421ea0dc2acbf1aa792e11c03d0c',True),
    ('22b70b80ac89ad3f3772526cd9feee2fa412c2b01933fea7ed13238a448d370d',True),
    ('22bc55c47af97246cfc093d0acf683a7869377de362b5d1c552c2c2e16b7a806',True),
    ('22c31a561553727960057361aa33bf20fb2e98584bc4fec007906e27053f80c6',True),
    ('253d739ba126f62a5767d832765b12b59e9f8d2bc88cc1572f4a73e46eb298ca',True),
    ('26d4021f6898e23b82ef953078389dd49ac2b5618ac564ade4ef87cced147b38',False),
    ('275a59b5406ff18c01739860aa70ad7ccb3cfb474579411decca11c93b951080',True),
    ('27b8c79ef57efe08efccbd9dd6ef70d61b4798320b8d3c134fd571f78963dbcd',True),
    ('2ae1d8f4238ec67d7185d8861cb0a2cdf4bc608697c331b95bf990e69b62e64a',True),
    ('2b31ffcc9bdc8295b2167e07a757dbbc9ac8906e7028e5170a3708cecaac119f',True),
    ('2ce69b1af49952cd4121a9c3055faa679e748ce774c7f1fda9657f936cae902f',True),
    ('2d2bad780a9f2b9195a4a370314d2c17ae95eaa745cefc2e12fbc49759b15aa3',True),
    ('2ddfb553fdf02fb784c234c7ba6ccc288296ceabec964ad2eae3777778130bc5',False),
    ('2f0222a6f229f0bf44cd711dc13c858dad98c62d52bd51d8fc3a764a83125513',True),
    ('2f14b7e8a1aa2f67ae92bc69d1ec0fa8d9f827c4e17ff5e5f02e91caa3b2d0fe',True),
    ('2f8d20d3b7d54143213c4dfc3d98225c42de7d666011528dc8fe91591e2e17b0',True),
    ('2faa4794364282db7c06600b7e5e34867a564ae91bda7cae7c29c64e9466b7d5',True),
    ('2fb3fb53675f6adfc1ca5bfbd5cfb655ae350fba4706d924a8ec7e3ba945671c',True),
    ('2ff292be6ef3340325ce8a045ecc326e92cbfab47c7cbab4bd85d28971b97ac4',True),
    ('30962b96c0c223483ed6cc7280e7f0199feb01a0e40cfae4d4450fc6fab1f570',False),
    ('3120d80c5861aa616222ec015332e5f8d3171e062e3e804a2a0253e1be26e59b',True),
    ('31271aedc59e815656f5736f282bb7509a97c7ecb43e927ac1a37966e0578075',True),
    ('31b206f67165b3536dd577c5c3f1518e8fbaf38cbc57efff8369a392feff1721',False),
    ('3264d826794ff8770d49e949ce16614800c73c5447d389aeb9f2b6bf569afa1d',False),
    ('32880f5e2945ce6a03d1fbd588e9198c0a959bb42297b2cfaf1685b7bc32e138',True),
    ('33c2dfa286578573afc55a7acaea3cada4122b9631007c594bf0729f41c8de92',True),
    ('33f6f999e03183f7d088c9be518a63467dfd0be94a11d0055fe2d210f89aa909',True),
    ('3548faea4ee5dda5580f9af150e79d0f6aea934fc60c1cc50f4efdd9420759e7',True),
    ('364b4e6ff19067c022997c0b11f1853090774ed800161a1b3397fd696b07c0b4',False),
    ('37bcdb4440fbb61df6a1c296ae01b327f19e9bb521f9b8e26ec854b6f97309ed',True),
    ('384fd68ffd952ef0a55f901a597da323f95fd3b460ca8093e3f68d1e7918fd88',False),
    ('38e4454b25fc30f15439c0378e57909ab1fd0a443158aa35aec685da727cd713',True),
    ('39f89066c12c24097854e8f57ab8558929f9c8d474d34b2c00ac04630ad8940e',True),
    ('3a83f095183f66345ca86aa13c58b59f9f94a2f81999c093d4eeaa2d262d12f4',True),
    ('3b5b49006181f5f8ff626ef8ddceaa95e9bb8ad294f7b5d7b11ea9f7ddaf8c59',True),
    ('3b772976fec7bdcda1d84b9d39b176589424c047eb2175bed09aac630e50af43',False),
    ('3bd40978e7a1fac911d5989e6b09d8f64921865a45822d8b09e815eaa726a651',True),
    ('3e036c4ad8d804a4dad897d333d8dce200d943df4827cb849840055be8d2e937',True),
    ('402e618f1fd065367775e8a5d71f6a4f4362e86d7e66215a43ec461ed5d1d071',False),
    ('40c97d1144356f52905566c55811f13b299453a14ac7769dfba2ac38192337a8',True),
    ('42f5ac4d1fb7c55ad4073dc462b02d485ace4da6d7fc29b35acfa99e28f2cb7d',False),
    ('4386831f878dc47f89103c2359aa36b880391cdcf05b7d0758d01a807b70198c',False),
    ('4460ec36adc8f722a6a2a4ac9374cb91f2acebadaa93fc37966129afb3dece87',True),
    ('44fe84260e454ed94ad326352a698422dbe372b21a1ac9f3eab76eb531223686',True),
    ('45061ff025b301940f1e30d2c16bea596c25b176c8b6b3087e92615adbd52902',True),
    ('465ec33805d3b964abe5fc58a0cb0da2da5bbeefe881ea155940df542ae38c39',False),
    ('48809ab0091b07ad0182defb787c4c5328bd3a278938415c00a7b69b50c4d3a8',True),
    ('494900a80f944fc7aa61500c2073d9729dff0b764f0e89b824eb746959bc1046',True),
    ('49d6e28aa38a37d75c7abc7c13e9850b63ddfd0d8ab8bebbff7fb9d16c4224b7',False),
    ('49ffccf0511cb8414de28321f5fcf2a31312b47c40cc21577144b7447f2bf300',True),
    ('4a09f199545a60d09895e8281362b1ff3bb08bbde69c6fc87aff5b92fcc916ca',True),
    ('4a87a60c927b56ddd67db50c89acaa62f4ce2a1d2149ccb63ffd871d5ce29ebc',True),
    ('4b4200e6cbf8fa335b2c3f43e1d6ef3e240319c33d43d60cc0fbd4b87ece299d',True),
    ('4c690e5fbae2f21e87843e89c26191f0d9454f362d8acdbd695716493ec8b3a9',False),
    ('4d5b36a8f4b6bc49023ba8328b5ae81a1f4ade42d6602f3d1d3fcbdf869c4595',True),
    ('4d964f874b251abc280ee28f0f187de3c13a6122a9561524f66a10768ca2d837',False),
    ('4f1d9991f5acc0ca119f9d443620b77f9d6b33703e51011c16baf57afb285fc6',False),
    ('4f9a1c5269aa17ebda5e6d3c2b89d6cbf36f7d2b22a0306e9ab98f25f95529c6',False),
    ('50dece891cfdf1741ea230d001aa9c14398062f2b7c066470accace78e412bc2',True),
    ('51f2312901470cdab0dbdf3b88c40cd21c62a7ed58a3de45b365ddc5b11bcab2',True),
    ('52d1c00a80a8cc67acbd01649e83d8dd6a9dc426a6c0b754a04fe8c219c76468',True),
    ('530c3beb3067e870561739f1144329a21c851ff771cd752a49e06e3dc9c2e71a',True),
    ('5426f412d0a7fc6b611643376c7e4a82dec991491b9ce5cb1cfdd25fe2e92be4',True),
    ('555f8686b4c7d6b5ba731fbea13bf656b4bfd9a7ff629c1d9d3f6e1d6155de79',True),
    ('557c3457560ff49e122ed76c0bc3397a64af9574691cb8201b4e46d4ab2ecb95',True),
    ('557ddc3a96858ec0d465a87c0a931054d7dcfd6583af2c7ed3baf494407fd8d0',True),
    ('55c570405f142630c6b9f72fe09d9b67cf1477fcf543ae5b8dcb1f5b7377da81',False),
    ('5733b54ea419d5eaf7997054bb55f6a1d0b5ff8aedf0176fef9eea44f3acda37',True),
    ('579c505165ee757a4280ef83cda0150eea193eed3bef50b1004ba88b99da6de6',True),
    ('5809fa3efab15d1f3c3c635af6974044bac8a4919c62238cce06acee8a8c11f1',True),
    ('58b029e5e901d6802967754adf0a9056747e8176f017cfe3607c0851f4d42216',True),
    ('59adcdf28230d220f0067b1f435b8537dd033bfff8db21335ef9217919c7fb58',True),
    ('5a78a7ae82cd1a33cef56dc578c7d2a46ed0dca12643ee45edbb8417899e6f74',True),
    ('5b1df97dbc29623bccdf2b0dcd0f5cb08e2f2c9050aab1092fd39a41e82686ff',True),
    ('5e463fbfba7b1701d957555ed45097d7f984211330106ccd1352c6e0af0dcf91',True),
    ('5eff717c18bb513285b499add68f2331509cd4e411ff085e96a86b3342c1e5aa',False),
    ('5f0700eaa9a33770aae4ae8b06bec8e433f518eb50711378c8cd3a5d7854ff2d',False),
    ('5fba48bbe0ba48761f9e9f75f92876cafb5d07c0ce059cc7a8027416de94a05b',True),
    ('5ff391bd9c9829d63cb1830c3d9a68970096b02d578fddce9985242c6013a475',False),
    ('621eeee06c4458a9121d1f104efb80f39d34deff4984e778359c60eaf1a8cb65',True),
    ('6241d35983510143049943fc0d57937937122baf1b287862f9dc8590fc4c37df',True),
    ('627e9ab0247f7d1e05736b59dbb1b6871373de5ad31c3011880b4133cafd4bd0',True),
    ('6461c1c5744442b394f46645957d6bd3420eb1b421908fe63caa03091b1b3655',False),
    ('65fab701d9829d38cb77c14acdc431d2108bfdbf8979e40eb8ae567edf10b27c',False),
    ('6704c35f7b4a72502ee81f61bf88706b54f06b3cbe5558ac17e2e14666cd5dcc',True),
    ('675642261665d8eea09989aa3b8afb5c37627f1be178382c320d1b46afba5e3b',True),
    ('686b06abe565edfab151cb8fd385a05651e1fdf8f0a14191e4439283421f8684',False),
    ('687e98a471973b5c5fd711750c40b8b82c0ade33f649db65e00b290f29345a2b',False),
    ('6900fdc8a9e95866b8c0d4ad4aba4d4236317b5c1cd04c502df3f0d33afed680',True),
    ('6915987c90970493ab97393024c156ea8fb9f3bea953b2f3ec05c34f19b5695c',True),
    ('69ad6927098316848b34a9142bcc975e018ba27f08c4ff403f50c1b6e646ca67',True),
    ('69cc88207ce91347ea530b227ff0776db82dcb8de6704e1a3d74f4841bc651cf',False),
    ('6a0a4a75a57aa6dc888300d848053a58c6b12a29f89d4304e1c41448514ec6e8',True),
    ('6b5fbb433f760a99a22b18b6850ed5784ef0e9928a72668b66e4d7ccd47db9b0',True),
    ('6de1edc1d26cafb0ea1a6ab3f4d4192d91a312fd2d360b63adaa213cd00b2108',True),
    ('6f7b417dcc794d9add9e556673ad25cb3ba835224290f4f848f8e2db1e1fca74',True),
    ('6fd3b1e1a38ca744f9664be4627ced80895c7d2ee353891c172f1ab61309c933',False),
    ('70390338f7a5106231d20620712f7cccb659cd0e9d073d1991c038eb9fc57589',True),
    ('7060193196395f5dd668eda046ccbeacebfd98efc77fed418dbe2b82ffaa39fd',True),
    ('70a3a0f9757bfb89fb28f250a121b34baa9916a77243ddf714c2344a409c595c',False),
    ('7298990c00040a0e2f121f6c32544bab27d4452f80d9ce51349b1a28f3005c43',True),
    ('72997b29dfd95c3fa0d0c48322d05590418edef451f8db8db5509c57875fb4b7',True),
    ('72c8f5cf9d26427cee6c76c8e3853eb46ce6b0412a081b2b6db6e8ad56267400',True),
    ('72e76b0eea4e81611ef5452aa82b3da34caca0c8b7b5c0c9584338aa93bae26b',True),
    ('72f1506841c920a1afec76975b35312410eea3aa7b63267436bfb1dd91d2d382',True),
    ('72fd4a0ede9ee5c021f6a8dd92b503e089f46c227ba2813ff183b71616034814',True),
    ('7336d5511ad5af0b8615fdc7477535a2e4e723a357b6713af439fe8cf0195017',True),
    ('73939767a4686cd9a520d16af5ab440071ed75cec1a876bf2fcfaf1f71987a16',True),
    ('742075a428ad12a3fa18a69014c2f57f01af910c6d9d18646c990200853e641a',True),
    ('746bf13cac0860f091df5e4911d0c593971cd8796b5ad4e809b2f8e133eee3d5',True),
    ('751c9940dcfe869f5f7274e1295422a34623555916eb98c174c1e945594bf198',True),
    ('75aab2373a4bbe2a1260b9bf2a1ebbdbf872d3bd36f80bff058dccd82e89422f',True),
    ('75b5fec090dbd46cf9b7d8ea08cf84a0472d92ba3585b476f44c326eda8059c4',True),
    ('75e10f767a433d9a86e50d83f418e83efc18ede923ee5ff7df93b6cb0306c5d4',False),
    ('7661303b8fc1b4d7f532e54e9d6565771fea666fbdf839e0a86affcd02defe87',True),
    ('76df3dfbd209dd4cd0be82b3c973a206817aa24ff8bb81b471bd096bea65172d',False),
    ('76e10fd4a48038d3fc7c5dc6e63b7063bbf5304a2e3bd42edda6ec660eebea68',True),
    ('77890552ecea9e284b5424c9de827a58099348763a4359e975c359a83d4faa83',True),
    ('7873b60be88844a0a1d8f80b9d5d20cfbd8495a689b8763e76c6372998d3f64c',True),
    ('7ad77c1e8c1b84222d9b3f3cae016a76639435744c19330b0b37c0a3c9da7dc0',True),
    ('7b63435aa19cc6a0cfd1a82fbdf2c7a2f0a94db1a79ff7a4469ffa94286261ab',False),
    ('7c2eb3dcfc53b0f3d6f9acdfd911ca803eaf92aadf54f8ca6e4c1f3aee288351',True),
    ('7cd0312e064fde87c8d1cd79ba06c876bd23630c83466e9500321be55c96ace2',True),
    ('7ceeefe9aec63a1064c18d939bdc3adf2d8aa1988a510afec15151578b232aa2',False),
    ('7e04ad8f8d5bea40451cf80b1bd8262552aa73f841415d20db96b7241bd027d8',True),
    ('7eb48e5ee1a4a5dcf94777ac654b7a302932b289ea06bc994da3b557245e6831',True),
    ('80f55196fb5d5cfc38224c1de52f3dc0f3f0e406a20761d31dad4a3ad8f8d265',False),
    ('812d2dd42f65dca362152101fbec418029cc8fd34cbad1a2fde905383d705838',True),
    ('8361d57eafb67c09b75bf4bbe6be360e1b8f4f18118ab48037f2bd50aa2ccb13',True),
    ('836e76439f354b89afe6a911a7adf59a6b2518fafb174483ad78a2a2fde7b1c5',True),
    ('865b3d334bd0f769587737447410d8042d6a95134cc45be5380805fdbacd7152',False),
    ('87c759916472441a640e82934772997e2cc9ac6f14ac447eb8aaa4ec0c1e07e3',False),
    ('88469e5d80540afa6bb081048b98a9c2ab74255f1def7fab2e0a016137a00ba4',False),
    ('885151d58d90d8d9c811eb75e3288c11f850e1d6b481a8c9f766adee4712358b',True),
    ('88ade7293becda963e0e3ea33e7d54d3425127e0a326e0d17da085a5f1f03ff6',True),
    ('88af1c246226d87e65be78ed49ecd1e6f5e98648558c14ce99176da041dc378e',True),
    ('88dfc9361e8b5ae1008ac38f7cdfd45ad738e4fa676a3ad67d19204f045a1fd8',True),
    ('89047429cb0207707b2dface14ba7f8df85273d484c2572755be4bab7ce9c3a0',True),
    ('895f21909c6fba01d7c17914bb6c8e135982275a1b18cdaa4e62272217ef1751',True),
    ('8991ad45bdc25018301d6b7e1d3626afc3c8af8aaf4bc04f23d0b99c938b73a6',True),
    ('89cd2866a9cb07fee9ff74c41ceace11554f32e0d849de4e23ac55515cfada4d',True),
    ('8a28e4aff06ee60aed2a8c281907fb8bcbf3b753c91fb5a5c57da3215d5b3497',True),
    ('8a43b7df601a7ec1af61d79345c17b31ea1fedc6711fd4abfd013ea612978e39',True),
    ('8b8dc9d2a4c88609409c3191165bccec0e4cb044cd7a72ccbe826583303459f6',True),
    ('8cb8efaf200bdeb2150d93e162c40f388529a25852b332cec879373771e48ed5',True),
    ('8ee81e1708756f81b343a5eb2b2f0b953f1d25c4ab3d4a68dc02754872e80715',True),
    ('8f679097876a9b609ad1f60249c49d68bfab783dd9be012faf9d82547b14815a',True),
    ('8fdee2dbaace6c252131c00e1de4b165dc65af02ea278476187765e1a617b917',True),
    ('9039681f9bcb8958ee2c87ffc74bdafba9f4369096a2b5634b88abc0eaefa072',True),
    ('9208ee05fd48bf09ac60ed269791cf17fb343db56c8226a720fbb1cdf467166c',True),
    ('93137d3aab9afa9b27cb06a824c2324195c6b6f6179d8a8653f440f5bd58be88',False),
    ('939de3e7a6161af0c887ef91b7d41a53e7c5a1ca976325f429cb46ea9bc30ecc',False),
    ('93a43dc47ee570e6ec9f5779b2e64c1476a6ce921c48cc9a1678a91dd5f8fd58',True),
    ('94e192033ca8027f26de71c9000a67ef9c73695c2b88e2c559045170917ead0c',True),
    ('96370666d2676a6fb19e0ed75be487f2e9c0c7a969c13cb248f361847ff9a81f',True),
    ('964c85c82cfeb6f3855e6a07054fdb159aced38e99a5eecf7bce9d53990afa3e',True),
    ('964e9268b37edb64e9a0fa525e5b5e535ba56bf63cadc68375f92e69fcb734f6',True),
    ('967ea2597bb7ef445c940d1ec41cd4d986e807ab03227efa96c03390d5d6baf9',False),
    ('9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23',False),
    ('9b328e31ee156f53f3c416a64f8491f7eb731742655a47c9eec4703a71644aee',True),
    ('9e8d11661d4ae3bd57702a3832781e23ad151dde5798e16a5ccd503f65234ff8',False),
    ('9f142c03e348f6d263719f5074b21ef3adf0b139ee4c5133e2aa35664da9eb2d',True),
    ('a04756d367a2126c3541682864ecec52f92cdee80a35735a3cb249ce015ca000',True),
    ('a0556fefca0b1bb2de8567b8827518f94db6a6e7e7d632b4c48dc5f865bc7c85',True),
    ('a0dcb779424be33100dcae821e9e27e4f2901d9dfd5333efe5ac6a8d7ab75e1d',True),
    ('a14b62d05969a293b80257e72e597c2da7f717e1e69fa8b339703ed6731bec87',True),
    ('a1e351607f04fed296ba33c4977d3fe2a615ed50df7896676b67aac993c53c18',False),
    ('a35d9561b3fc5b18797c330793e99e3b834a473d5fbd3d7d7634aafc9bdb6f8f',True),
    ('a4ec4f2db570171e3e5eb753276ee4b389bae16b96207e9d3230895c99644b86',True),
    ('a52c89e54cc311196e478f8382df91c15f7a2bfdf4c6cd0e2675cc2ff0b56efb',True),
    ('a56b85e418c83eb1839819f0b515c431010160383306d13ec21959ac412d2fe7',True),
    ('a58c25c5fe063a70057fa20cb8e15f3bda19b1030305bcb533af1e45f36a4a55',False),
    ('a5a29bb89544f9b97edce05642fac225a808b5b7be74038ea3640fae2f8e66a7',True),
    ('a70cf1bba851000ba93b58ae2f6d76490a9feb74192e57ab8e8ff13c34ec50cb',True),
    ('a7a7b6ce9bee418c1a760b3d84f83a299ad6952f9903c67f19e4edd964894e06',True),
    ('a7fda60eefdf3d8c827262ba499957e4df06f659330bbe6cdbdb975b768bb65c',True),
    ('a835fe55fbdcd8e80f38584ab22d0840662c67f2feb36bd679402da9641dc71e',False),
    ('a97c7678c19f236a956ad260d59c86e10a463badb7eb2eda787490f4c969b963',True),
    ('a9a703e4f15ebebb7f664bcb8ca0a87320880aa87fa55adbe49d47a3eb53b287',False),
    ('a9ffb62ba1d8e9ebad5225bd2cde6e8ff20688060fff8d14133ca9bb237fb48b',False),
    ('abad668ff2fd63ada1ac49bf386d37e27048b89a3465a6fd968bb832b00a09d3',True),
    ('abba66c3b767dc7ecb7b7060932761aef646fb57bbe498ac9ccf8f2da3e3088d',False),
    ('abf360251023dfe3efcef65ab9d56beefa8394d4176dd29529750e1c57eaa33f',True),
    ('ac1824ed5edf17dee2fdd4927ada30c9f8c3b520be1b5fd02a5da15bc10bff3e',True),
    ('ac2c3213df8f985785f1d0aeb7f0f73d5324e6e67d593d9b9470fb74a25d4a9b',True),
    ('ad6eeef431dc52aefd2d77ed20a4b353f8ebf0f4ecdd26a807d2da5aa8cd0615',True),
    ('ae74fb96c20a0277a1d615f1e4d73c8414f5a98db8b799a7931d1582f3390c28',False),
    ('b038c0c07e12e658135bbc32cc1a2ded6e33785105c9d41958014c592de4593e',True),
    ('b47e3c83a0c1440ce335aa1ae18753da6eb7cd551d4946fa303de2abde07e20b',False),
    ('b4963dda9b31080be1905ef085ecd7dd6cd47c05c79b9cdf83ade83ab2ab271a',True),
    ('b51d82b561a78ab21d265107b0edbf98d68a390b4103992d0b03258bb3819601',False),
    ('b5663f69581dcf391293fbf16c06cb80d81d806545ce618b4d0bab7f0eb8c428',False),
    ('b5c17f90458caae90d2ccd114c81970062946f49f355610ed89bebf954f5783c',True),
    ('b607e9b9234790a008116ae5bdb71c6243b84b9fb42a53a9e70fde41c06c536a',False),
    ('ba0d021a166865d2265246961bec0152ff124de910c5cc39f1156ce3fa7c69dc',False),
    ('bcb0fd896384802d1ad283b4e4eb4d718eebd8cb820b0a2c3a347fb971afd9d8',True),
    ('bd0786e0f8b6aed8c35898b4c06f64ba853d61d7c8361edb5a8d43c6ea37f5c6',False),
    ('bd82e5d7b9ce2d31e380dd9f50c111d678c3bdaca190cb76b0e1c71b05e1ba8a',True),
    ('bdf3a12fbd6c12600d717404b3912406e47f1aebab86913c287e407b1bc9bbfe',False),
    ('bf93870767689637164657731849fb887ad086739bd5d360d90007a581d5527d',True),
    ('c26b4e69cf02fea24511a108d158188b9d8174426311aac59ce803a78d107648',False),
    ('c3a9c4211ff4c309edb8b8c4f1cbfa7ae324c4ba9f91ff254e3d305b9fd54561',False),
    ('c43dabc564990eeab55e25ed61c07a1aadafe9ece96a4efabb3f8bf9063b71ef',True),
    ('c4a89e7ceb9bf1e25cf84a9f830ff6b817b72874088bf5141b314726e46a57c1',True),
    ('c7f6948dae6999bf0db32c1858ae345f112cacf98f174c7a8bb707e41b974f1c',True),
    ('c86a20ffbb78fef68e867e3048e2a4f949bac41ddcb353daccf190130d098842',False),
    ('c998e060b85f71e00de5ec552019347c8bca255062c990ac02d051bb80a38df0',True),
    ('c9e8c682bf75b0e7c704166d79b599f93b72cfca5ad7477df596947891feeef6',True),
    ('cb2aa0747f84c6c3a78dad4e2049c154f08ab9d166b1273835a8174940365647',True),
    ('cb3d511531b16cfc78a225a9e2136007a48cf8a677e4264baeab57fe78a80206',True),
    ('cba2573d870babc976664a912539b320cbaa7114cd3e8f053c720171cde331ed',True),
    ('cc82bc96f2997baa545ab3ce73f196d040ffb8756fd2d66125a530031cd90e5f',True),
    ('cd06d15dd8bb59926e4d65f9003bfc20f9da4b2519985c27e190cddc8b7a7806',False),
    ('cdcafe83ec318cda34e02948e81d790aab8df7a929cec6f6969f13a489ccecd9',True),
    ('cdf8cbe5ee750db04b78878c9633cc76e80dcf4416cbe982ac3a9222f80713c8',True),
    ('ce916b775a62b90b61888052a416ccdda405212b6aaeb39522f7dc53431a5e73',True),
    ('cea3901d7e299da7320700abbaafe57a65d039f10d0d7ea601c4a66938ea4b0c',True),
    ('cfbcbf3e6eac06ef9d85900f64424708cc08687d1b527f0ef65aa7517af8118f',True),
    ('d01f995ecd137abf30238ad9ce97f8fc3ac57289c8b24bd0bf53324d937a14f8',True),
    ('d209fdb6f36ffaf61c509fcc81b19e81b411a999a934a032e10cd009a0226215',True),
    ('d20c951960ed77cb7b341c2a59488534e494d5ad1d30c4818c736d57772a9fef',False),
    ('d253ae36a8bd9ee3c5955384096ccb6baf16a1b1e93e858370da0a3b94f77c16',True),
    ('d269a01a18ee74d0335450b10f62c9ed81f2321d7958a2934e44272fe82dcef3',True),
    ('d38ff6e517149dc509406aca0db3ad1efdd890a85e049585b7234d04238e2a4d',True),
    ('d8a9e38cc5228881f7055a6079f6f7821a073df3744d441978e7a43e20226939',True),
    ('d9351ba35217ad0de03816ef3ed63f89d411349353077348a45348b096615036',True),
    ('dbad4a23abcca6171e47b79edc53bd6a41067a3b75f9e8b104656b459ff25046',True),
    ('dbec758171594a705933a29fcf69293d2468c49ec1f2ebca65c36f504d72df46',True),
    ('dce197b859eb796242b0622af1b8beb0a722d52aa2f57133ead08edd5bf5374e',False),
    ('de4402cd12f4cc8fda2354fce179fdb068c0b9ca1ec2d2b17b3e21b24c1a937b',True),
    ('deed3094f7cc779ed1d37a68403847b0e38d9dd9d931e03cb90825f3368b515f',True),
    ('defa2226f06ba20550d6548c3a2ea2a7929634437a52973869c20c225450eb91',True),
    ('df85e46410ff71c4006a13dbdeeeee488feba563be78f3a9ed8497c1fb93fb5d',True),
    ('df99f03fc7934a4737122518bb87e667e62d780b610910f0447665a7e2be62dc',True),
    ('e2e7c2defabbcc79aa605e7b7efa306439adcf02fc0b332bc82881dfa51f315a',False),
    ('e3386e6ff4529f2442800dee47ad28d3e6487f36a1f75ae39ae56c70f0cd2fbd',True),
    ('e45b6bb2350aff3e442ae1111c555e27eac1d915e77775f6fdc4b351b758b5d7',True),
    ('e6986b41626ee10bdc864937ffb6d6bf275bb5b9c65120e6137d56e6331f089e',True),
    ('e6b87c89bd0b27039e3af2c5da01147452f240f75d505f5b6880874f31036307',False),
    ('e6f4c20442eaa7c90d7190d8dc539d0ab422f95c65a57cc59562170c58ae3d34',True),
    ('e717beabc4d091ecb2c803c2d341b88590e9116b8bf7947915eeb33aab4f96dd',True),
    ('e85761f3098a6faf40b8187695e3de6d97944e98abd0d8ce579cb2daf6319a66',True),
    ('e8dff86b0971688790ae75528fe1813f71809b5afd57facb44dad9e8eca631b7',True),
    ('e986a9fe25aeaa84ac17ca093ef13a4637f6107375f64667a15999f77db6c8f6',True),
    ('ec1705118f7eaedd6e118508d3d26deba2a4e76476ada7e0e3965211be012002',True),
    ('ed11f9a5883b0b7d9895811fda5c83e62807f273c621641dbf9484bae3f4d053',False),
    ('ee0618755913ef7fd6511288a232e8fad24838b9af6ea73972a76e81053c8c2d',False),
    ('eec517b5bbe5492629466e11dae908d043364302283de25581e3eb944326c4ca',True),
    ('eecdd666eda6be16a8d9dc15e44b5c75133405e820f620a234acc4b1fdc5aa37',True),
    ('ef5f255c5b5d90cfb415da9dd63faedce948beaf5ce39c528aa681f7d1e8a21f',False),
    ('ef85697305025e5a61f395d4eaede272a5393cee479ace6686dba707de804d59',True),
    ('f05feb42b48f1b3c225e4ccf351f367be0371411a803198ec34a389fb22aa580',True),
    ('f1df20f0bf22c28192a794f29b501ee2018fa37a3862a1a2132ae2940a23a642',True),
    ('f35baf9da0efe45fa3da1696ae906eea3d615ad41e2e3def4aeb4e8bc0ef9a7a',True),
    ('f448c6e8963fdfa7eb831457df83ad63d3d6355018f6574fb017e8169deb43a9',True),
    ('f4808e2ab5b0197f094cabce9f4b006a27766beb6a9975931da07099560ca9c2',True),
    ('f609f341d6e9090b981b3f45324d05a819fd7a5a56434f849c761971ce2c47da',False),
    ('f75a361704fa902544f8104cf8bdabc571586d50de0d290a1da6ece741816b9a',False),
    ('f75e8807570484a99be90abcd52b5e1f390362c258bcb73106f4544957a48101',True),
    ('f8c3486509de705192138b00ef2c00bbbdd0e84c30d5c07d23fc73a9dc4cc9cc',False),
    ('f9382337dd5a474c3b7d334c2f83e50b6eaedc284253334cf823044a26de03e8',True),
    ('f93b6dd7ce796b13d02c108bc9f79812245a82e577581c4c9aabe57075c90ea2',False),
    ('f9690195445f6ed298781d1a49e09014de08e00a0c778b60e4bc888154279fed',False),
    ('fa7b512dfcb5eafd90ce3959cf42a2a6fe96144ebbb4b3b3928054895f2afac2',True),
    ('fa92e2eb41a04df73cdabeec37107316f7e5272650f81d6cc096418fe647b915',True),
    ('fb8d25550742674d63d7b250063d4580ca530499f045d70748b1b142081ebb92',True),
    ('fc152419aa2ea0f51c29583fab1e8c99ddefd5b3778421845606ee628629e0e5',True),
    ('fca665e2431e02de2b0c7aeb21f9f566a3833f9687f31e0fe986c486bacc9647',True),
    ('fcf351c47596c939140ab0d333dfdd08ed1ea6ce33c2fe70c12493a301cf1344',True),
    ('fd1ac84bc4e97a5a0816b7fd7d4d4f6d837b0047cf4cbd81652d616af3a6591a',True),
    ('fda8a652ab3c7d8fee214de05e7a9916d8b28082234e8d2c0094505c5268ed3c',True),
)

# Default HTTP canonical IDs derive from exact ordered URL inputs, not cache markers.
# BCR registry mirrors are pinned empty; custom repository downloads without a
# declared HTTP canonical ID remain outside this finite marker declaration.
CANONICAL_IDS=(
    ('01b2e0ef893383a50dbeb13970fe7fa3be36ca3e83259e01649945b09d736985','https://github.com/pinterest/ktlint/releases/download/1.3.0/ktlint'),
    ('05d1933f0a5ba7d8d6296bb6d5018e7c94fa473ceb10cf198a92ccea19c27b53','https://files.pythonhosted.org/packages/e5/ca/1172b6638d52f2d6caa2dd262ec4c811ba59eee96d54a7701930726bce18/installer-0.7.0-py3-none-any.whl'),
    ('06367c5178e365ff9d9df48ab28e6b080c344a06f52cb01157df881739d2cb14','https://github.com/bazelbuild/apple_support/releases/download/2.5.4/apple_support.2.5.4.tar.gz'),
    ('0e1ed4a98f26e718776bd64d053d02bb34d98572ccd03d6ba355112a1205706b','https://github.com/bazelbuild/stardoc/releases/download/0.7.2/stardoc-0.7.2.tar.gz'),
    ('0e89367f1cb6d93a5a1afea4b55b11ea6b28f63f653b47154153677ca7d4afea','https://github.com/bazel-contrib/supply-chain/releases/download/v0.0.3/supply-chain-v0.0.3.tar.gz'),
    ('14a225870ab4e91869652cfd69ef2028277fc1dc4910d65d353b62d6e0ae21f4','https://github.com/bazelbuild/rules_proto/releases/download/7.1.0/rules_proto-7.1.0.tar.gz'),
    ('1692f77d1739bacf3f94337188b78583cf09bab7e420d2dc6c5605a4f86785a1','https://github.com/abseil/abseil-cpp/releases/download/20250814.1/abseil-cpp-20250814.1.tar.gz'),
    ('1de5b47721fce0af0dd453b3071228fdfc44bd18199826b3f0b03b423aae9f65','https://github.com/bazelbuild/rules_cc/releases/download/0.2.18/rules_cc-0.2.18.tar.gz'),
    ('20152b14d9a420afc15ace905c02fd6425ddceb084630f3f043b287adf0fcdbd','https://github.com/bazelbuild/rules_apple/releases/download/4.1.0/rules_apple.4.1.0.tar.gz'),
    ('26d4021f6898e23b82ef953078389dd49ac2b5618ac564ade4ef87cced147b38','https://github.com/bazelbuild/rules_license/releases/download/1.0.0/rules_license-1.0.0.tar.gz'),
    ('2ddfb553fdf02fb784c234c7ba6ccc288296ceabec964ad2eae3777778130bc5','https://files.pythonhosted.org/packages/49/df/1fceb2f8900f8639e278b056416d49134fb8d84c5942ffaa01ad34782422/packaging-24.0-py3-none-any.whl'),
    ('30962b96c0c223483ed6cc7280e7f0199feb01a0e40cfae4d4450fc6fab1f570','https://files.pythonhosted.org/packages/2d/0a/679461c511447ffaf176567d5c496d1de27cbe34a87df6677d7171b2fbd4/importlib_metadata-7.1.0-py3-none-any.whl'),
    ('31b206f67165b3536dd577c5c3f1518e8fbaf38cbc57efff8369a392feff1721','https://files.pythonhosted.org/packages/25/6e/ca4a5434eb0e502210f591b97537d322546e4833dcb4d470a48c375c5540/pep517-0.13.1-py3-none-any.whl'),
    ('3b5b49006181f5f8ff626ef8ddceaa95e9bb8ad294f7b5d7b11ea9f7ddaf8c59','https://github.com/bazelbuild/bazel-skylib/releases/download/1.9.0/bazel-skylib-1.9.0.tar.gz'),
    ('3b772976fec7bdcda1d84b9d39b176589424c047eb2175bed09aac630e50af43','https://github.com/bazelbuild/rules_kotlin/releases/download/v1.9.6/rules_kotlin-v1.9.6.tar.gz'),
    ('42f5ac4d1fb7c55ad4073dc462b02d485ace4da6d7fc29b35acfa99e28f2cb7d','https://codeberg.org/ziglang/arocc/archive/d0c8c4d9c55daa7ef6e40cf0f630a5b5e900989b.tar.gz'),
    ('465ec33805d3b964abe5fc58a0cb0da2da5bbeefe881ea155940df542ae38c39','https://codeberg.org/ziglang/translate-c/archive/0da7a16c3235b935b82421646076e0657cda21f6.tar.gz'),
    ('4c690e5fbae2f21e87843e89c26191f0d9454f362d8acdbd695716493ec8b3a9','https://files.pythonhosted.org/packages/0d/dc/38f4ce065e92c66f058ea7a368a9c5de4e702272b479c0992059f7693941/pip_tools-7.4.1-py3-none-any.whl'),
    ('4d964f874b251abc280ee28f0f187de3c13a6122a9561524f66a10768ca2d837','https://github.com/apple/swift-argument-parser/archive/refs/tags/1.3.1.tar.gz'),
    ('4f1d9991f5acc0ca119f9d443620b77f9d6b33703e51011c16baf57afb285fc6','https://files.pythonhosted.org/packages/d1/d6/3965ed04c63042e047cb6a3e6ed1a63a35087b6a609aa3a15ed8ac56c221/colorama-0.4.6-py2.py3-none-any.whl'),
    ('55c570405f142630c6b9f72fe09d9b67cf1477fcf543ae5b8dcb1f5b7377da81','https://files.pythonhosted.org/packages/7d/cd/d7460c9a869b16c3dd4e1e403cce337df165368c71d6af229a74699622ce/wheel-0.43.0-py3-none-any.whl'),
    ('5eff717c18bb513285b499add68f2331509cd4e411ff085e96a86b3342c1e5aa','https://github.com/bazelbuild/rules_swift/releases/download/3.1.2/rules_swift.3.1.2.tar.gz'),
    ('6461c1c5744442b394f46645957d6bd3420eb1b421908fe63caa03091b1b3655','https://github.com/bazelbuild/rules_android/archive/refs/tags/v0.1.1.tar.gz'),
    ('65fab701d9829d38cb77c14acdc431d2108bfdbf8979e40eb8ae567edf10b27c','https://github.com/google/googletest/releases/download/v1.17.0/googletest-1.17.0.tar.gz'),
    ('686b06abe565edfab151cb8fd385a05651e1fdf8f0a14191e4439283421f8684','https://files.pythonhosted.org/packages/50/e2/8e10e465ee3987bb7c9ab69efb91d867d93959095f4807db102d07995d94/more_itertools-10.2.0-py3-none-any.whl'),
    ('687e98a471973b5c5fd711750c40b8b82c0ade33f649db65e00b290f29345a2b','https://github.com/protocolbuffers/protobuf/releases/download/v33.4/protobuf-33.4.bazel.tar.gz'),
    ('69cc88207ce91347ea530b227ff0776db82dcb8de6704e1a3d74f4841bc651cf','https://github.com/nlohmann/json/releases/download/v3.6.1/include.zip'),
    ('6fd3b1e1a38ca744f9664be4627ced80895c7d2ee353891c172f1ab61309c933','https://github.com/bazel-contrib/bazel-lib/releases/download/v3.0.0/bazel-lib-v3.0.0.tar.gz'),
    ('75e10f767a433d9a86e50d83f418e83efc18ede923ee5ff7df93b6cb0306c5d4','https://files.pythonhosted.org/packages/e2/03/f3c8ba0a6b6e30d7d18c40faab90807c9bb5e9a1e3b2fe2008af624a9c97/build-1.2.1-py3-none-any.whl'),
    ('7b63435aa19cc6a0cfd1a82fbdf2c7a2f0a94db1a79ff7a4469ffa94286261ab','https://github.com/bazel-contrib/jq.bzl/releases/download/v0.1.0/jq.bzl-v0.1.0.tar.gz'),
    ('7ceeefe9aec63a1064c18d939bdc3adf2d8aa1988a510afec15151578b232aa2','https://files.pythonhosted.org/packages/ae/f3/431b9d5fe7d14af7a32340792ef43b8a714e7726f1d7b69cc4e8e7a3f1d7/pyproject_hooks-1.1.0-py3-none-any.whl'),
    ('865b3d334bd0f769587737447410d8042d6a95134cc45be5380805fdbacd7152','https://github.com/bazelbuild/rules_java/releases/download/9.0.3/rules_java-9.0.3.tar.gz'),
    ('939de3e7a6161af0c887ef91b7d41a53e7c5a1ca976325f429cb46ea9bc30ecc','https://files.pythonhosted.org/packages/97/75/10a9ebee3fd790d20926a90a2547f0bf78f371b2f13aa822c759680ca7b9/tomli-2.0.1-py3-none-any.whl'),
    ('94e192033ca8027f26de71c9000a67ef9c73695c2b88e2c559045170917ead0c','https://github.com/bazel-contrib/bazel-lib/releases/download/v2.22.5/bazel-lib-v2.22.5.tar.gz'),
    ('9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23','https://github.com/madler/zlib/releases/download/v1.3.1/zlib-1.3.1.tar.gz'),
    ('a1e351607f04fed296ba33c4977d3fe2a615ed50df7896676b67aac993c53c18','https://github.com/bazel-contrib/rules_jvm_external/releases/download/6.7/rules_jvm_external-6.7.tar.gz'),
    ('a58c25c5fe063a70057fa20cb8e15f3bda19b1030305bcb533af1e45f36a4a55','https://github.com/pybind/pybind11_bazel/releases/download/v2.12.0/pybind11_bazel-2.12.0.zip'),
    ('a835fe55fbdcd8e80f38584ab22d0840662c67f2feb36bd679402da9641dc71e','https://github.com/google/re2/releases/download/2024-07-02/re2-2024-07-02.zip'),
    ('ae74fb96c20a0277a1d615f1e4d73c8414f5a98db8b799a7931d1582f3390c28','https://files.pythonhosted.org/packages/00/2e/d53fa4befbf2cfa713304affc7ca780ce4fc1fd8710527771b58311a3229/click-8.1.7-py3-none-any.whl'),
    ('b47e3c83a0c1440ce335aa1ae18753da6eb7cd551d4946fa303de2abde07e20b','https://github.com/bazel-contrib/tar.bzl/releases/download/v0.5.1/tar.bzl-v0.5.1.tar.gz'),
    ('b51d82b561a78ab21d265107b0edbf98d68a390b4103992d0b03258bb3819601','https://github.com/bazel-contrib/yq.bzl/releases/download/v0.1.1/yq.bzl-v0.1.1.tar.gz'),
    ('ba0d021a166865d2265246961bec0152ff124de910c5cc39f1156ce3fa7c69dc','https://files.pythonhosted.org/packages/8a/6a/19e9fe04fca059ccf770861c7d5721ab4c2aebc539889e97c7977528a53b/pip-24.0-py3-none-any.whl'),
    ('bd0786e0f8b6aed8c35898b4c06f64ba853d61d7c8361edb5a8d43c6ea37f5c6','https://github.com/fmeum/buildozer/releases/download/v8.5.1/buildozer-v8.5.1.tar.gz'),
    ('c26b4e69cf02fea24511a108d158188b9d8174426311aac59ce803a78d107648','https://github.com/bazel-contrib/bazel_features/releases/download/v1.43.0/bazel_features-v1.43.0.tar.gz'),
    ('c3a9c4211ff4c309edb8b8c4f1cbfa7ae324c4ba9f91ff254e3d305b9fd54561','https://files.pythonhosted.org/packages/90/99/158ad0609729111163fc1f674a5a42f2605371a4cf036d0441070e2f7455/setuptools-78.1.1-py3-none-any.whl'),
    ('cd06d15dd8bb59926e4d65f9003bfc20f9da4b2519985c27e190cddc8b7a7806','https://github.com/bazelbuild/rules_android/archive/v0.1.1.zip'),
    ('d20c951960ed77cb7b341c2a59488534e494d5ad1d30c4818c736d57772a9fef','https://github.com/bazelbuild/rules_pkg/releases/download/1.0.1/rules_pkg-1.0.1.tar.gz'),
    ('dbad4a23abcca6171e47b79edc53bd6a41067a3b75f9e8b104656b459ff25046','https://github.com/bazelbuild/platforms/releases/download/1.1.0/platforms-1.1.0.tar.gz'),
    ('dce197b859eb796242b0622af1b8beb0a722d52aa2f57133ead08edd5bf5374e','https://files.pythonhosted.org/packages/da/55/a03fd7240714916507e1fcf7ae355bd9d9ed2e6db492595f1a67f61681be/zipp-3.18.2-py3-none-any.whl'),
    ('e6b87c89bd0b27039e3af2c5da01147452f240f75d505f5b6880874f31036307','https://github.com/bazelbuild/rules_shell/releases/download/v0.6.1/rules_shell-v0.6.1.tar.gz'),
    ('f609f341d6e9090b981b3f45324d05a819fd7a5a56434f849c761971ce2c47da','https://github.com/bazel-contrib/rules_python/releases/download/1.7.0/rules_python-1.7.0.tar.gz'),
    ('f8c3486509de705192138b00ef2c00bbbdd0e84c30d5c07d23fc73a9dc4cc9cc','https://ftp.gnu.org/gnu/gawk/gawk-5.3.2.tar.xz'),
    ('f93b6dd7ce796b13d02c108bc9f79812245a82e577581c4c9aabe57075c90ea2','https://github.com/open-source-parsers/jsoncpp/archive/refs/tags/1.9.6.tar.gz'),
    ('fca665e2431e02de2b0c7aeb21f9f566a3833f9687f31e0fe986c486bacc9647','https://github.com/hermeticbuild/rules_zig/archive/c81e777fe398186c9f0251ba1332a1d56f30d094.tar.gz'),
)
MAX_CANONICAL_IDS=256

def require(value):
    if not value:raise ValueError('fixed-yoga-controller-http-inputs-refused')

def cache_path(run):
    return Path(run)/NAME

def identity(info):
    return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_nlink,
        info.st_size,info.st_mtime_ns,info.st_ctime_ns)

def directory_identity(info):
    return (info.st_dev,info.st_ino,info.st_uid,stat.S_IMODE(info.st_mode))

def directories(path):
    path=Path(path)
    require(path.is_absolute() and '..' not in path.parts and len(path.parts)<=32)
    held=[];names=[]
    try:
        held.append(os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW))
        for name in path.parts[1:]:
            descriptor=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=held[-1])
            held.append(descriptor);names.append(name)
            info=os.fstat(descriptor)
            require(info.st_uid in (0,os.getuid()) and not info.st_mode&0o022)
        return held,names
    except BaseException:
        for descriptor in reversed(held):os.close(descriptor)
        raise

def members(descriptor,expected,budget):
    observed=set()
    with os.scandir(descriptor) as entries:
        for entry in entries:
            budget();require(len(observed)<len(expected) and entry.name in expected)
            observed.add(entry.name)
    require(observed==set(expected))

def digest_file(descriptor,budget,maximum,output=None):
    before=os.fstat(descriptor)
    require(stat.S_ISREG(before.st_mode) and before.st_uid in (0,os.getuid())
        and before.st_nlink==1 and not before.st_mode&0o022 and 0<before.st_size<=maximum)
    os.lseek(descriptor,0,os.SEEK_SET)
    value=hashlib.sha256();size=0
    while True:
        budget()
        chunk=os.read(descriptor,min(65536,maximum+1-size))
        if not chunk:break
        size+=len(chunk);require(size<=maximum);value.update(chunk)
        if output is not None:
            view=memoryview(chunk)
            while view:
                budget();written=os.write(output,view);require(written>0);view=view[written:]
    require(size==before.st_size and identity(before)==identity(os.fstat(descriptor)))
    return value.hexdigest(),size

def canonical_marker(canonical_id):
    require(type(canonical_id) is str and 0<len(canonical_id)<=32768 and '\x00' not in canonical_id)
    return 'id-'+hashlib.sha256(canonical_id.encode('utf-8')).hexdigest()

def zero_marker(descriptor,budget):
    budget();before=os.fstat(descriptor)
    require(stat.S_ISREG(before.st_mode) and before.st_uid==os.getuid()
        and before.st_nlink==1 and stat.S_IMODE(before.st_mode)==0o444 and before.st_size==0)
    os.lseek(descriptor,0,os.SEEK_SET)
    require(os.read(descriptor,1)==b'' and identity(before)==identity(os.fstat(descriptor)))

class Snapshot:
    def __init__(self,run,entry,deadline):
        self.entry,self.deadline=entry,deadline
        self.path=cache_path(run);self.held=[];self.parents=[];self.names=[]
        self.rows=[];self.marker_rows=[];self.marker_names={};self.links=[];self.missing=0;self.total=0;self.verified_after_cleanup=False;self.custody_released=False
        try:
            self.budget()
            require(len(DECLARED)<=512 and len({sha for sha,_ in DECLARED})==len(DECLARED))
            require(len(CANONICAL_IDS)<=MAX_CANONICAL_IDS)
            declared={sha for sha,_ in DECLARED}
            for sha,canonical_id in CANONICAL_IDS:
                require(sha in declared)
                marker=canonical_marker(canonical_id)
                names=self.marker_names.setdefault(sha,[])
                require(marker not in names);names.append(marker)
            # Bind copied bytes to the exact locked source family.
            source,names=directories(SOURCE_ROOT)
            try:
                for name,expected in (('MODULE.bazel',MODULE_SHA256),('MODULE.bazel.lock',LOCK_SHA256)):
                    descriptor=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=source[-1])
                    try:require(digest_file(descriptor,self.budget,1024**2)[0]==expected)
                    finally:os.close(descriptor)
            finally:
                for descriptor in reversed(source):os.close(descriptor)
            self.parents,self.names=directories(Path(run))
            require(os.fstat(self.parents[-1]).st_uid==os.getuid()
                and stat.S_IMODE(os.fstat(self.parents[-1]).st_mode)==0o700)
            os.mkdir(NAME,0o700,dir_fd=self.parents[-1])
            root=os.open(NAME,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=self.parents[-1])
            self.held.append(root)
            os.mkdir('content_addressable',0o700,dir_fd=root)
            content=os.open('content_addressable',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=root)
            self.held.append(content)
            os.mkdir('sha256',0o700,dir_fd=content)
            hashes=os.open('sha256',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=content)
            self.held.append(hashes)
            self.links=[(root,'content_addressable',content),(content,'sha256',hashes)]
            origin,origin_names=directories(CACHE/'content_addressable'/'sha256')
            try:
                for expected,required in DECLARED:
                    self.budget()
                    source_directory=None;source_file=None
                    try:
                        try:source_directory=os.open(expected,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=origin[-1])
                        except FileNotFoundError:
                            require(not required);self.missing+=1;continue
                        info=os.fstat(source_directory)
                        require(info.st_uid in (0,os.getuid()) and not info.st_mode&0o022)
                        # A present declared directory with a missing/refused leaf
                        # is corruption, not optional absence.
                        source_file=os.open('file',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=source_directory)
                        os.mkdir(expected,0o700,dir_fd=hashes)
                        destination=os.open(expected,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=hashes)
                        self.held.append(destination)
                        self.links.append((hashes,expected,destination))
                        output=os.open('file',os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=destination)
                        try:
                            value,size=digest_file(source_file,self.budget,min(MAX_FILE,MAX_TOTAL-self.total),output)
                            require(value==expected and identity(os.fstat(source_file))==
                                identity(os.stat('file',dir_fd=source_directory,follow_symlinks=False)))
                            self.total+=size
                            os.fchmod(output,0o444)
                            os.fsync(output)
                        finally:os.close(output)
                        # Publish only declared URL bindings after the payload digest matched.
                        # These zero-byte entries are derived, never copied/discovered from origin cache.
                        for marker in self.marker_names.get(expected,()):
                            self.budget()
                            output_marker=os.open(marker,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,
                                0o600,dir_fd=destination)
                            try:
                                os.fchmod(output_marker,0o444);os.fsync(output_marker)
                            finally:os.close(output_marker)
                            marker_capture=os.open(marker,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=destination)
                            self.held.append(marker_capture)
                            zero_marker(marker_capture,self.budget)
                            self.marker_rows.append((expected,destination,marker,marker_capture,identity(os.fstat(marker_capture))))
                        os.fchmod(destination,0o555)
                        capture=os.open('file',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=destination)
                        self.held.append(capture)
                        self.rows.append((expected,destination,capture,identity(os.fstat(capture))))
                    finally:
                        if source_file is not None:os.close(source_file)
                        if source_directory is not None:os.close(source_directory)
            finally:
                for descriptor in reversed(origin):os.close(descriptor)
            for descriptor in (hashes,content,root):os.fchmod(descriptor,0o555)
            # Pin identities after all creation/sealing mutations have finished.
            self.parent_identities=[directory_identity(os.fstat(fd)) for fd in self.parents]
            self.directory_identities=[(fd,directory_identity(os.fstat(fd))) for fd in self.held if stat.S_ISDIR(os.fstat(fd).st_mode)]
            self.recheck(content=True)
        except BaseException:
            self.close();raise

    def budget(self,cleanup=False):
        kernel.remaining(self.entry,self.deadline,cleanup=cleanup)

    def recheck(self,*,content=False,cleanup=False):
        require(bool(self.held))
        for index,descriptor in enumerate(self.parents):
            self.budget(cleanup)
            require(directory_identity(os.fstat(descriptor))==self.parent_identities[index])
            if index:
                require(directory_identity(os.stat(self.names[index-1],dir_fd=self.parents[index-1],follow_symlinks=False))
                    ==self.parent_identities[index])
        for descriptor,before in self.directory_identities:
            self.budget(cleanup);require(directory_identity(os.fstat(descriptor))==before)
        require(directory_identity(os.stat(NAME,dir_fd=self.parents[-1],follow_symlinks=False))
            ==self.directory_identities[0][1])
        for parent,name,descriptor in self.links:
            self.budget(cleanup)
            require(directory_identity(os.stat(name,dir_fd=parent,follow_symlinks=False))
                ==directory_identity(os.fstat(descriptor)))
        root,content_root,hashes=self.held[:3]
        budget=lambda:self.budget(cleanup)
        members(root,('content_addressable',),budget);members(content_root,('sha256',),budget)
        members(hashes,{sha for sha,_,_,_ in self.rows},budget)
        for sha,directory,descriptor,before in self.rows:
            members(directory,{'file',*self.marker_names.get(sha,())},budget)
            self.budget(cleanup)
            require(identity(os.fstat(descriptor))==before==
                identity(os.stat('file',dir_fd=directory,follow_symlinks=False)))
            if content:
                require(digest_file(descriptor,lambda:self.budget(cleanup),MAX_FILE)[0]==sha)
        for sha,directory,marker,descriptor,before in self.marker_rows:
            self.budget(cleanup)
            require(identity(os.fstat(descriptor))==before==
                identity(os.stat(marker,dir_fd=directory,follow_symlinks=False)))
            zero_marker(descriptor,lambda:self.budget(cleanup))
        if cleanup and content:self.verified_after_cleanup=True

    def binding(self):
        self.recheck()
        return str(self.path)+':'+str(self.path)+':rbind'

    def verify_binding(self,actual):
        require(actual.get('BindReadOnlyPaths','').split()==[self.binding()])
        require(not actual.get('BindPaths','').split())

    def facts(self):
        return {'scope':'fixed-yoga-controller-locked-http-snapshot-v1',
            'module_sha256':MODULE_SHA256,'lock_sha256':LOCK_SHA256,
            'declared_inputs':len(DECLARED),'copied_files':len(self.rows),'copied_bytes':self.total,
            'missing_optional_inputs':self.missing,'verified_after_cleanup':self.verified_after_cleanup,
            'snapshot_sha256':hashlib.sha256(json.dumps([(sha,before[5]) for sha,_,_,before in self.rows]+
                [('canonical-id',sha,marker,0) for sha,_,marker,_,_ in self.marker_rows],
                separators=(',',':')).encode()).hexdigest(),'custody_released':self.custody_released,
            'downloads_allowed':False,'complete_dependency_closure_proved':False}

    def close(self):
        failed=False
        for descriptor in reversed(self.held+self.parents):
            try:os.close(descriptor)
            except OSError:failed=True
        self.held=[];self.parents=[]
        self.custody_released=not failed
        if failed:raise ValueError('fixed-yoga-controller-http-release-refused')
