import * as z from 'zod/v4';

export const ShadowStackInfoSchema = z.object({
  AbnormalStackFrame: z.string(),
});
export type ShadowStackInfo = z.infer<typeof ShadowStackInfoSchema>;

const BaseSystemCallInfo = z.object({
  InvolvedSystemCall: z.string(),
  InvolvedSystemCallId: z.int().min(1).max(3),
});

export const SystemCallInfoSchema = z.union([
  BaseSystemCallInfo.extend({
    NtWriteVmInfo: z.object({
      SourceAddress: z.string(),
      TargetAddress: z.string(),
      Size: z.number(),
    }),
  }),
  BaseSystemCallInfo.extend({
    NtProtectVmInfo: z.object({
      BaseAddress: z.string(),
      NumberOfBytesToProtect: z.number(),
      Protection: z.number(),
    }),
  }),
  BaseSystemCallInfo.extend({
    NtWriteFileInfo: z.object({
      BufferAddress: z.string(),
      BufferLength: z.number(),
    }),
  }),
]);

export type SystemCallInfo = z.infer<typeof SystemCallInfoSchema>;

export const InfoSchema = z.object({
  Hollowed: z.boolean(),
  ProcessVadRootAddress: z.string(),
  ProcessBaseAddressVad: z.string(),
  ProcessBaseAddressLdr: z.string(),
});
export type Info = z.infer<typeof InfoSchema>;

export const CodeInjectionInfoSchema = z.object({
  SuspiciousStartAddress: z.string(),
  OriginMemoryRegionProtect: z
    .enum(['X', 'WX', 'RWX', 'RX', 'NX'])
    .describe('Execute, Write Execute, Read Execute, Read Write Execute, No Execute'),
});
export type CodeInjectionInfo = z.infer<typeof CodeInjectionInfoSchema>;

export const AbnormalNtSyscallInfoSchema = z.object({
  UserSyscallAddress: z.string(),
});
export type AbnormalNtSyscallInfo = z.infer<typeof AbnormalNtSyscallInfoSchema>;

export const CredentialDumpInfoSchema = z.object({
  OperationType: z.string(),
});
export type CredentialDumpInfo = z.infer<typeof CredentialDumpInfoSchema>;

export const RegistryOperationInfoSchema = z.object({
  SuspiciousRegistryKey: z.string(),
  SuspiciousRegistryValue: z.string(),
});
export type RegistryOperationInfo = z.infer<typeof RegistryOperationInfoSchema>;

export const SpecificEventsInfoSchema = z.union([
  z.object({ SystemCallInfo: SystemCallInfoSchema }),
  z.object({ GhostProcessInfo: InfoSchema }),
  z.object({ CodeInjectionInfo: CodeInjectionInfoSchema }),
  z.object({ AbnormalNtSyscallInfo: AbnormalNtSyscallInfoSchema }),
  z.object({ CredentialDumpInfo: CredentialDumpInfoSchema }),
  z.object({ RegistryOperationInfo: RegistryOperationInfoSchema }),
  z.object({ HollowedVadTreeInfo: InfoSchema }),
  z.object({ ShadowStackInfo: ShadowStackInfoSchema }),
]);

export type SpecificEventsInfo = z.infer<typeof SpecificEventsInfoSchema>;

export const DetectionEventSchema = z.object({
  Version: z.number(),
  GlobalDefensiveMethod: z.string(),
  GlobalDefensiveMethodId: z.int().min(1).max(8),
  Level: z.enum(['Critical', 'Info', 'Warning']),
  isCodeInjection: z.boolean(),
  OriginProcess: z.string(),
  OriginPID: z.number(),
  VictimProcess: z.string(),
  TargetPID: z.number(),
  OriginProcessImagePath: z.string(),
  InvolvedYaraRule: z.string(),
  DateAndTime: z.coerce.date(),
  SpecificEventsInfo: z.array(SpecificEventsInfoSchema),
});
export type DetectionEvent = z.infer<typeof DetectionEventSchema>;
