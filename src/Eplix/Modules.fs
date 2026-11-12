/// The modules this build links. Each one is behind an MSBuild property (see Eplix.fsproj).
module Eplix.Host.Modules

open Eplix

let all () : Module list =
    [
#if EPLIX_LOCAL
        Eplix.Backend.Local.LocalModule.create ()
#endif
#if EPLIX_DIRK
        Eplix.Backend.Dirk.DirkModule.create ()
#endif
#if EPLIX_WEB3SIGNER
        Eplix.Backend.Web3Signer.Web3SignerModule.create ()
#endif
#if EPLIX_TEE
        Eplix.Backend.Tee.TeeModule.create ()
#endif
#if EPLIX_KEYMANAGER
        Eplix.Keymanager.KeymanagerModule.create ()
#endif
#if EPLIX_GLOAS
        Eplix.Gloas.GloasModule.create ()
#endif
#if EPLIX_BUILDER
        Eplix.Builder.BuilderModule.create ()
#endif
#if EPLIX_BUILDER_LEGACY
        Eplix.BuilderLegacy.LegacyBuilderModule.create ()
#endif
#if EPLIX_METRICS
        Eplix.Metrics.MetricsModule.create ()
#endif
#if EPLIX_MONITOR
        Eplix.Monitor.MonitorModule.create ()
#endif
#if EPLIX_DOPPELGANGER
        Eplix.Doppelganger.DoppelgangerModule.create ()
#endif
#if EPLIX_OBOL
        Eplix.Obol.ObolModule.create ()
#endif
#if EPLIX_GRAFFITI
        Eplix.Graffiti.GraffitiModule.create ()
#endif
#if EPLIX_TRACING
        Eplix.Tracing.TracingModule.create ()
#endif
    ]
