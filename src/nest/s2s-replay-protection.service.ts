import { Injectable } from '@nestjs/common';
import { ReplayProtectionStore } from '../replay/replay-protection.store';

@Injectable()
export class S2SReplayProtectionService extends ReplayProtectionStore {}
