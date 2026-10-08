// Included only by the declared provider-free acquisition model target.
#include <QTemporaryDir>
#include <QFile>

struct CodexAcquisitionModels {
    static QJsonObject snapshot() {
        const QString source(64,'a'), account(64,'b'), grant(64,'c');
        return {{"custody_available",true},
            {"sources",QJsonArray{QJsonObject{{"id",source},{"provider","codex"},{"label","Synthetic source"},
                {"kind","native_store"},{"status","connected"},{"authorized_at",10},{"authorized_until",200}}}},
            {"accounts",QJsonArray{QJsonObject{{"id",account},{"lifecycle","active"},{"source_ids",QJsonArray{source}},
                {"identity",QJsonObject{{"provider","codex"},{"verified",true}}}}}},
            {"grants",QJsonArray{QJsonObject{{"id",grant},{"source_id",source},{"account_id",account},
                {"credential_kind","oauth_access"},{"ownership","external"},{"status","ready"},
                {"audience","https://chatgpt.com"},{"purposes",QJsonArray{"request","account_read"}},
                {"provider_expires_at",200},{"custody_expires_at",200},{"generation",7}}}},
            {"jobs",QJsonArray{QJsonObject{{"id","reconcile-"+source},{"kind","enrollment"},
                {"status","completed"},{"operation_generation",9}}}}};
    }
    static bool authority() {
        const QString source(64,'a'), job="reconcile-"+source;
        const auto valid=[](const QJsonObject &s) {
            return CodexAccountAcquisition::usableEnrollment(s,QString(64,'a'),"reconcile-"+QString(64,'a'),9,100);
        };
        auto s=snapshot(); if (!valid(s)) return false;
        auto sources=s.value("sources").toArray(); auto origin=sources[0].toObject();
        origin["authorized_until"]=100; sources[0]=origin; s["sources"]=sources;
        if (valid(s)) return false; // ready grant cannot borrow an expired source.
        s=snapshot(); sources=s.value("sources").toArray(); origin=sources[0].toObject();
        origin["status"]="disconnected"; sources[0]=origin; s["sources"]=sources; if (valid(s)) return false;
        origin["status"]="detached"; sources[0]=origin; s["sources"]=sources; if (!valid(s)) return false;
        origin["authorized_at"]=true; sources[0]=origin; s["sources"]=sources; if (valid(s)) return false;
        s=snapshot(); sources=s.value("sources").toArray(); origin=sources[0].toObject();
        origin["provider"]="github"; sources[0]=origin; s["sources"]=sources; if (valid(s)) return false;
        s=snapshot(); sources=s.value("sources").toArray(); origin=sources[0].toObject();
        origin["id"]=QString(64,'d'); origin["authorized_until"]=1; sources.append(origin); s["sources"]=sources;
        if (!valid(s)) return false; // unrelated expired source is not our lineage.
        auto jobs=s.value("jobs").toArray(); auto operation=jobs[0].toObject();
        operation["operation_generation"]=10; jobs[0]=operation; s["jobs"]=jobs; if (valid(s)) return false;
        s=snapshot(); jobs=s.value("jobs").toArray(); operation=jobs[0].toObject();
        operation["status"]="failed"; jobs[0]=operation; s["jobs"]=jobs; if (valid(s)) return false;
        for (const auto &key:{"provider_expires_at","custody_expires_at","generation"}) {
            s=snapshot(); auto grants=s.value("grants").toArray(); auto g=grants[0].toObject();
            g[key]=true; grants[0]=g; s["grants"]=grants; if (valid(s)) return false;
        }
        s=snapshot(); auto grants=s.value("grants").toArray(); auto g=grants[0].toObject();
        g["ownership"]="omux"; grants[0]=g; s["grants"]=grants; if (valid(s)) return false;
        s=snapshot(); s["custody_available"]=false; if (valid(s)) return false;
        return !CodexAccountAcquisition::usableEnrollment(snapshot(),source,job,8,100);
    }
    static bool wire() {
        QJsonObject frame;
        if (!CodexAccountAcquisition::parseNativeFrame(R"({"result":{},"id":1})",&frame)) return false;
        for (const auto &v : {QByteArray(R"({"id":1,"id":2,"result":{}})"),
            QByteArray(R"({"id":1,"\u0069d":1,"result":{}})"),
            QByteArray(R"({"result":{"success":true,"success":false}})"),
            QByteArray(R"({"result":{"nested":{"a":1,"\u0061":2}}})"),
            QByteArray(65537,'x'),QByteArray(R"({"result":)")})
            if (CodexAccountAcquisition::parseNativeFrame(v,&frame)) return false;
        return CodexAccountAcquisition::parseNativeFrame(R"({"method":"notice","params":{"array":[{"id":1},{"id":2}]}})",&frame);
    }
    static bool journal(const QString &root) {
        const auto parent=root+"/sources"; auto held=ensure(parent);
        const auto profile=parent+"/native-login-"+QString(32,'a');
        if (::mkdirat(held.value,("native-login-"+QString(32,'a')).toUtf8().constData(),0700)!=0) return false;
        OmuxClient client(root+"/unused-control.sock");
        CodexAccountAcquisition first(client,nullptr);
        first.phase_=CodexAccountAcquisition::Phase::Connecting; first.elapsed_.start();
        first.profile_=profile; first.connectID_=QString(64,'d'); first.enrollmentID_=QString(64,'e');
        first.connectRevision_=12;
        auto runtime=std::make_shared<CodexAcquisitionRuntime>();
        runtime->componentSha=QString(64,'f'); runtime->sourceParentPath=parent;
        runtime->sourceParent=FD(::dup(held.value)); runtime->profile=directory(profile); runtime->profilePath=profile;
        first.runtime_=runtime;
        first.checkpoint("source-connect-pending");
        const auto raw=read(runtime->intent.value,16384); const auto record=json(raw);
        if (record.value("connect_params").toObject().value("expected_revision")!=12
            || record.value("connect_params").toObject().value("operation_id")!=first.connectID_
            || record.value("enrollment_params").toObject().value("expected_revision").isDouble()) return false;
        // A second UI instance recovers the same intent, without a native child
        // or any mutation dispatch. Its client only tracks the original identity.
        OmuxClient recoveredClient(root+"/unused-control.sock");
        CodexAccountAcquisition second(recoveredClient,nullptr);
        second.phase_=CodexAccountAcquisition::Phase::Preparing; second.elapsed_.start();
        auto recovered=std::make_shared<CodexAcquisitionRuntime>();
        recovered->sourceParentPath=parent; recovered->sourceParent=directory(parent);
        second.runtime_=recovered;
        if (!second.recoverIntent() || second.connectID_!=first.connectID_ || second.enrollmentID_!=first.enrollmentID_
            || second.connectRevision_!=12 || !recoveredClient.hasUncertainOperations()
            || second.native_.state()!=QProcess::NotRunning) return false;
        if (second.operationEvent({{"operation_kind","mutation"},{"operation_id",QString(64,'0')},{"operation_status","completed"}})) return false;
        second.operationEvent({{"operation_kind","mutation"},{"operation_id",first.connectID_},{"operation_status","not_found"}});
        FD pointer(::openat(held.value,"active.json",O_RDONLY|O_NOFOLLOW|O_CLOEXEC)); if (pointer.value<0) return false;
        if (read(runtime->intent.value,16384)!=raw) return false;
        first.elapsed_.invalidate();
        bool refused=false; try { first.checkpoint("source-connect-pending"); } catch (...) { refused=true; }
        if (!refused || read(runtime->intent.value,16384)!=raw) return false;
        // Same-inode ancestor alias must fail the actual publication recheck.
        first.elapsed_.start();
        if (::rename(parent.toUtf8().constData(),(root+"/saved").toUtf8().constData())!=0
            || ::symlink("saved",parent.toUtf8().constData())!=0) return false;
        refused=false; try { first.checkpoint("source-connect-pending"); } catch (...) { refused=true; }
        if (!refused || read(runtime->intent.value,16384)!=raw) return false;
        if (::unlink(parent.toUtf8().constData())!=0 || ::rename((root+"/saved").toUtf8().constData(),parent.toUtf8().constData())!=0) return false;
        // A same-path/same-content replacement is not the held active pointer.
        const auto activeRaw=read(runtime->active.value,4096);
        if (::renameat(held.value,"active.json",held.value,"old-active.json")!=0) return false;
        FD replacement(::openat(held.value,"active.json",O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600));
        if (replacement.value<0 || ::write(replacement.value,activeRaw.constData(),size_t(activeRaw.size()))!=activeRaw.size()) return false;
        refused=false; try { first.checkpoint("source-connect-pending"); } catch (...) { refused=true; }
        return refused && read(runtime->intent.value,16384)==raw;
    }
    static bool freshIntent(const QString &root) {
        OmuxClient client(root+"/new-intent-control.sock"); CodexAccountAcquisition next(client,nullptr);
        next.connectRevision_=12; next.enrollmentRevision_=27;
        next.connectID_=QString(64,'d'); next.enrollmentID_=QString(64,'e');
        // A ready snapshot is required before any journal or mutation. The
        // actual fresh-operation entry clears the previous account's revision
        // even when the new daemon observation is unavailable.
        next.connectSource();
        return next.connectRevision_==-1 && next.enrollmentRevision_==-1
            && next.connectID_!=QString(64,'d') && next.enrollmentID_!=QString(64,'e')
            && next.connectID_!=next.enrollmentID_ && !next.busy()
            && !client.hasUncertainOperations();
    }
    static bool recoveredConnection(const QString &root) {
        const auto parent=root+"/recovery-sources"; auto held=ensure(parent);
        const auto profile=parent+"/native-login-"+QString(32,'b');
        if (::mkdirat(held.value,("native-login-"+QString(32,'b')).toUtf8().constData(),0700)!=0) return false;
        OmuxClient originalClient(root+"/recovery-control.sock");
        CodexAccountAcquisition original(originalClient,nullptr);
        original.phase_=CodexAccountAcquisition::Phase::Connecting; original.elapsed_.start();
        original.profile_=profile; original.connectID_=QString(64,'d'); original.enrollmentID_=QString(64,'e');
        original.connectRevision_=12;
        auto runtime=std::make_shared<CodexAcquisitionRuntime>();
        runtime->componentSha=QString(64,'f'); runtime->sourceParentPath=parent;
        runtime->sourceParent=FD(::dup(held.value)); runtime->profile=directory(profile); runtime->profilePath=profile;
        original.runtime_=runtime; original.checkpoint("source-connect-pending");
        const auto intent=read(runtime->intent.value,16384);
        OmuxClient recoveredClient(root+"/recovery-control.sock");
        CodexAccountAcquisition recovered(recoveredClient,nullptr);
        recovered.phase_=CodexAccountAcquisition::Phase::Preparing; recovered.elapsed_.start();
        auto selected=std::make_shared<CodexAcquisitionRuntime>();
        selected->sourceParentPath=parent; selected->sourceParent=directory(parent); recovered.runtime_=selected;
        QString source,message;
        recovered.onSourceConnected=[&](const QString &v) { source=v; };
        recovered.onStatus=[&](const QString &v) { message=v; };
        if (!recovered.recoverIntent()) return false;
        // An original source-connect ACK recovered after UI destruction must
        // select the connected source, not dispatch a new enrollment mutation
        // under a newly started clock. The existing Enroll control owns that
        // subsequent explicit user intent.
        if (!recovered.operationEvent({{"operation_kind","mutation"},{"operation_id",original.connectID_},
            {"operation_status","completed"},{"operation_result",QJsonObject{
                {"source_id",QString(64,'a')},{"status","authorized"},{"identity_admission","verification_required"}}}})) return false;
        struct stat pointer{};
        return !recovered.busy() && source==QString(64,'a')
            && recovered.enrollmentRevision_==-1 && recovered.jobID_.isEmpty()
            && recovered.native_.state()==QProcess::NotRunning && message.contains("no workflow effect was replayed")
            && read(runtime->intent.value,16384)==intent
            && ::fstatat(held.value,"active.json",&pointer,AT_SYMLINK_NOFOLLOW)<0 && errno==ENOENT;
    }
    static bool component(const QString &root) {
        const auto data=root+"/data", state=root+"/state", parent=data+"/omux-acquisition/codex",
            record=state+"/omux-acquisition/codex", leaf=parent+"/"+backendPin;
        auto dataFD=ensure(parent), stateFD=ensure(record);
        const auto writeFixture=[](const QString &path,const QByteArray &raw,int mode) {
            if (!QDir().mkpath(QFileInfo(path).absolutePath())) return false;
            QFile file(path);
            if (!file.open(QIODevice::WriteOnly) || file.write(raw)!=raw.size()) return false;
            file.close(); return ::chmod(path.toUtf8().constData(),mode)==0;
        };
        QJsonObject rows;
        const auto file=[&](const QString &relative,const QByteArray &raw,int mode) {
            if (!writeFixture(leaf+"/"+relative,raw,mode)) return false;
            rows.insert(relative,QJsonObject{{"sha256",digest(raw)},{"bytes",raw.size()},{"mode",mode}});
            return true;
        };
        if (!file("codex",modelRuntimeBytes,0555)) return false;
        for (auto it=runtimePolicy.begin();it!=runtimePolicy.end();++it)
            if (!file("runtime/"+it.key(),modelRuntimeBytes,it->mode)) return false;
        const auto makeOuter=[](const char *label) {
            return QJsonObject{{"id","11111111-2222-4333-8444-555555555555"},
                {"artifact_epoch","11111111-2222-4333-8444-555555555555"},
                {"source_commit",QString(40,'a')},{"graph_sha256",QString(64,'b')},{"source_dirty","false"},
                {"profile","standard"},{"manager","system"},{"verb","test"},{"targets",QJsonArray{label}},
                {"exit",0},{"workload_exit",0},{"controller_failure",QJsonValue()},{"descendants_empty",true},
                {"cleanup",QJsonObject{{"state","empty"}}},{"test_evidence",QJsonObject{{"state","preserved"}}},
                {"codex_owner_runtime_input",QJsonObject{{"verified_after_cleanup",true}}}};
        };
        const auto outer=makeOuter("//tools:codex_retained_device_api_qualification");
        // Spaced/indented actual guard JSON must not require compact encoding.
        const auto outerRaw=QJsonDocument(outer).toJson(QJsonDocument::Indented);
        const QJsonObject props{{"type",QJsonObject{{"type","string"},{"enum",QJsonArray{"chatgptDeviceCode"}}}}};
        QJsonObject responseProps=props;
        for (const auto *key:{"loginId","verificationUrl","userCode"}) responseProps.insert(key,QJsonObject{{"type","string"}});
        const QJsonObject inner{{"schema_version",1},{"kind","omux-retained-device-api-qualification-v1"},
            {"status","provider-free-device-api-qualified"},
            {"archive_sha256","0094334d7fd27b81f613ebe734305412bd13f95f1f3396ba2f0396168e5223ad"},{"archive_bytes",119923125},
            {"manifest_sha256","5626b375f0f3c1818340345c952394ef44b59acbc177ab83f7b910c6fb105678"},
            {"source_receipt_sha256","e3c6d45bc93119ddf1da8bee6e02de3c7c3a3bbe52bb6d2664eb4b7b3d7b5273"},
            {"producer_receipt_sha256","545727183aa4e361eb1967fa3599dd30e5fd38a78f68dad9fec74793f8f713ee"},
            {"backend_sha256",backendPin},{"backend_bytes",backendBytes},
            {"loader_sha256",runtimePolicy.value("lib/codex/lib/ld-linux-x86-64.so.2").sha},
            {"version","codex 0.0.0"},{"runtime_inventory",policyJson()},
            {"runtime_inventory_sha256",digest(QJsonDocument(policyJson()).toJson(QJsonDocument::Compact)+'\n')},
            {"native_support",false},{"text_continuity",false},{"provider_evaluation",false},
            {"device_api",QJsonObject{{"method","account/login/start"},{"provider_invocation",false},
                {"request",QJsonObject{{"type","object"},{"properties",props},{"required",QJsonArray{"type"}}}},
                {"response",QJsonObject{{"type","object"},{"properties",responseProps},
                    {"required",QJsonArray{"type","loginId","verificationUrl","userCode"}}}}}}};
        const auto innerRaw=QJsonDocument(inner).toJson(QJsonDocument::Compact)+'\n';
        if (!file("native-source-receipt.json",innerRaw,0444) || !file("qualification.json",outerRaw,0444)) return false;
        const auto projection=[](const QByteArray &raw,const QJsonObject &v) {
            return QJsonObject{{"sha256",digest(raw)},{"bytes",raw.size()},{"id",v.value("id")},
                {"source_commit",v.value("source_commit")},{"graph_sha256",v.value("graph_sha256")}};
        };
        const QJsonObject descriptor{{"schema_version",1},{"scope","omux-codex-device-acquisition-component-v1"},
            {"purpose","device-account-acquisition"},{"system","x86_64-linux"},{"backend_sha256",backendPin},
            {"files",rows},{"qualification",QJsonObject{
                {"inner",QJsonObject{{"sha256",digest(innerRaw)},{"bytes",innerRaw.size()}}},
                {"outer",projection(outerRaw,outer)}}},{"version","codex 0.0.0"},{"renewal_owner","native"},
            {"native_support",false},{"text_continuity",false},{"provider_evaluation",false}};
        const auto descriptorRaw=QJsonDocument(descriptor).toJson(QJsonDocument::Compact)+'\n';
        if (!file("component.json",descriptorRaw,0444)) return false;
        auto producer=makeOuter("//delivery:codex_device_acquisition_component");
        producer["profile"]="codex-device-component";
        producer["codex_device_component"]=QJsonObject{{"verified_after_cleanup",true},
            {"original_entry_monotonic_ns",qint64(1000000)},{"original_deadline_monotonic_ns",qint64(1200001000000)},
            {"input",QJsonObject{{"scope","provider-free-codex-device-component"},{"action","produce"},{"manifest_sha256",QString(64,'d')},
                {"provider_request_performed",false},{"native_execution_performed",false},{"resident_effects_authorized",false},
                {"continuity_qualified",false},{"credential_contents_read",false}}},
            {"output",QJsonObject{{"action_epoch",producer.value("id")},{"controller_graph_sha256",producer.value("graph_sha256")},
                {"manifest_sha256",QString(64,'d')},{"action","produce"},{"provider_request_performed",false},
                {"resident_enrollment_completed",false},{"continuity_qualified",false}}}};
        const auto producerRaw=QJsonDocument(producer).toJson(QJsonDocument::Indented);
        const QJsonObject installation{{"schema_version",1},{"scope","omux-codex-device-acquisition-install-v1"},
            {"component_sha256",digest(descriptorRaw)},{"backend_sha256",backendPin},{"data_home",data},{"state_home",state},
            {"qualification_sha256",digest(outerRaw)},{"device_receipt_sha256",digest(innerRaw)},
            {"descriptor_bytes",descriptorRaw.size()},{"files",rows},{"producer",projection(producerRaw,producer)}};
        if (!writeFixture(record+"/producer.json",producerRaw,0600)
            || !writeFixture(record+"/install.json",QJsonDocument(installation).toJson(QJsonDocument::Compact)+'\n',0600)
            || !writeFixture(parent+"/.lock","",0600)
            || !writeFixture(parent+"/current.json",QJsonDocument(QJsonObject{{"schema_version",1},
                {"scope","omux-codex-device-acquisition-selection-v1"},{"component_sha256",digest(descriptorRaw)},
                {"backend_sha256",backendPin}}).toJson(QJsonDocument::Compact)+'\n',0600)) return false;
        const auto seal=[&](const auto &self,const QString &path)->bool {
            QDir dir(path);
            for (const auto &child:dir.entryInfoList(QDir::Dirs|QDir::NoDotAndDotDot))
                if (!self(self,child.absoluteFilePath())) return false;
            return ::chmod(path.toUtf8().constData(),0555)==0;
        };
        if (!seal(seal,leaf)) return false;
        qputenv("XDG_DATA_HOME",data.toUtf8()); qputenv("XDG_STATE_HOME",state.toUtf8());
        {
            CodexAcquisitionRuntime selected; selected.prepare();
            if (!selected.error.isEmpty() || selected.backend.value<0 || selected.loader.value<0) return false;
            // Actual shared lease blocks replacement throughout retained use.
            FD exclusive(::openat(dataFD.value,".lock",O_RDWR|O_NOFOLLOW|O_CLOEXEC));
            if (exclusive.value<0 || ::flock(exclusive.value,LOCK_EX|LOCK_NB)==0) return false;
            selected.recheck(); selected.recheck();
            entries(dataFD.value,{".lock","current.json",backendPin}); entries(dataFD.value,{".lock","current.json",backendPin});
        }
        // Even independently rehashed valid-shaped receipts must obey the
        // package producer's closed no-effect and original-clock contract.
        const auto rejectedProducer=[&](const QJsonObject &candidate) {
            const auto raw=QJsonDocument(candidate).toJson(QJsonDocument::Indented);
            auto joined=installation; joined["producer"]=projection(raw,candidate);
            if (!writeFixture(record+"/producer.json",raw,0600)
                || !writeFixture(record+"/install.json",QJsonDocument(joined).toJson(QJsonDocument::Compact)+'\n',0600)) return false;
            CodexAcquisitionRuntime invalid; invalid.prepare(); return !invalid.error.isEmpty();
        };
        for (const auto *field:{"provider_request_performed","native_execution_performed","resident_effects_authorized",
            "continuity_qualified","credential_contents_read"}) {
            auto wrong=producer; auto context=wrong.value("codex_device_component").toObject();
            auto input=context.value("input").toObject(); input[field]=true; context["input"]=input;
            wrong["codex_device_component"]=context; if (!rejectedProducer(wrong)) return false;
        }
        for (const auto &clock:QJsonArray{QJsonValue(),true,qint64(1200001000001)}) {
            auto wrong=producer; auto context=wrong.value("codex_device_component").toObject();
            context["original_deadline_monotonic_ns"]=clock; wrong["codex_device_component"]=context;
            if (!rejectedProducer(wrong)) return false;
        }
        if (!writeFixture(record+"/producer.json",producerRaw,0600)
            || !writeFixture(record+"/install.json",QJsonDocument(installation).toJson(QJsonDocument::Compact)+'\n',0600)) return false;
        // A valid-shaped producer cannot borrow an old raw receipt digest.
        auto changed=producer; changed["workload_exit"]=1;
        if (!writeFixture(record+"/producer.json",QJsonDocument(changed).toJson(QJsonDocument::Indented),0600)) return false;
        CodexAcquisitionRuntime failed; failed.prepare(); if (failed.error.isEmpty()) return false;
        if (!writeFixture(record+"/producer.json",producerRaw,0600)) return false;
        // An extra sealed runtime member is not authorized by a complete map.
        if (::chmod((leaf+"/runtime/lib/codex/lib").toUtf8().constData(),0700)!=0
            || !writeFixture(leaf+"/runtime/lib/codex/lib/extra.so",modelRuntimeBytes,0555)
            || ::chmod((leaf+"/runtime/lib/codex/lib").toUtf8().constData(),0555)!=0) return false;
        CodexAcquisitionRuntime extra; extra.prepare();
        return !extra.error.isEmpty();
    }
    static bool protocolNoFalseSuccess(const QString &root) {
        OmuxClient client(root+"/unused-protocol.sock"); CodexAccountAcquisition acq(client,nullptr);
        QString status; acq.onStatus=[&](const QString &message) { status=message; };
        acq.phase_=CodexAccountAcquisition::Phase::Consent; acq.custodyAvailable_=true;
        acq.loginID_="synthetic-opaque-login"; acq.elapsed_.start();
        // Even a matching success notification without our actual reaped clean
        // native child and held output cannot advance to source mutation.
        acq.frame({{"method","account/login/completed"},{"params",QJsonObject{{"loginId","synthetic-opaque-login"},{"success",true}}}});
        if (acq.busy() || acq.sourceID_.size()!=0 || status.contains("identity verified")) return false;
        acq.phase_=CodexAccountAcquisition::Phase::Consent; acq.loginID_="synthetic-opaque-login";
        acq.frame({{"method","account/login/completed"},{"params",QJsonObject{{"loginId","unrelated-login"},{"success",true}}}});
        return !acq.busy() && !acq.completed_;
    }
};
int main(int argc,char **argv) {
    if (argc!=3) return 1;
    const QFileInfo plugin(QString::fromLocal8Bit(argv[1])), fonts(QString::fromLocal8Bit(argv[2]));
    if (!plugin.isFile() || plugin.fileName()!="libqoffscreen.so" || !fonts.isFile()) return 2;
    qputenv("QT_QPA_PLATFORM","offscreen");
    qputenv("QT_QPA_PLATFORM_PLUGIN_PATH",plugin.absolutePath().toUtf8());
    qputenv("QT_PLUGIN_PATH",QDir(plugin.absolutePath()).absoluteFilePath("..").toUtf8());
    qputenv("FONTCONFIG_FILE",fonts.absoluteFilePath().toUtf8());
    QTemporaryDir root("/tmp/omux-acquisition-model-XXXXXX");
    if (!root.isValid() || ::chmod(root.path().toUtf8().constData(),0700)!=0) return 3;
    for (const auto *name:{"XDG_CONFIG_HOME","XDG_DATA_HOME","XDG_CACHE_HOME","XDG_STATE_HOME","XDG_RUNTIME_DIR"})
        qputenv(name,root.path().toUtf8());
    struct RestoreFixtureModes {
        QString path;
        ~RestoreFixtureModes() {
            const auto unseal=[](const auto &self,const QString &path)->void {
                if (QFileInfo(path).isSymLink()) return;
                ::chmod(path.toUtf8().constData(),0700);
                for (const auto &child:QDir(path).entryInfoList(QDir::Dirs|QDir::NoDotAndDotDot))
                    if (!child.isSymLink()) self(self,child.absoluteFilePath());
            };
            unseal(unseal,path);
        }
    } fixtureCleanup{root.path()};
    QApplication app(argc,argv);
    if (!CodexAcquisitionModels::wire()) return 4;
    if (!CodexAcquisitionModels::authority()) return 5;
    if (!CodexAcquisitionModels::journal(root.path())) return 6;
    if (!CodexAcquisitionModels::protocolNoFalseSuccess(root.path())) return 7;
    if (!CodexAcquisitionModels::component(root.path())) return 8;
    if (!CodexAcquisitionModels::recoveredConnection(root.path())) return 9;
    if (!CodexAcquisitionModels::freshIntent(root.path())) return 10;
    return 0;
}
