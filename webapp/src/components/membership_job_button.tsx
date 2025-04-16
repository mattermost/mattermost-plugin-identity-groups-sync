// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

import React, {useState, useEffect} from 'react';

import Client from '../client';

interface JobStatus {
    running: boolean;
}

const MembershipJobButton: React.FC = () => {
    const [isRunning, setIsRunning] = useState(false);
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    const checkJobStatus = async () => {
        try {
            setIsLoading(true);
            const status: JobStatus = await Client.checkSyncJobRunning();
            setIsRunning(status.running);
            setError(null);
        } catch (err) {
            setError('Failed to check job status');
        } finally {
            setIsLoading(false);
        }
    };

    useEffect(() => {
        // Initial check when component mounts
        checkJobStatus();

        // Set up polling every 10 seconds
        const intervalId = setInterval(() => {
            checkJobStatus();
        }, 10000);

        // Clean up interval on unmount
        return () => clearInterval(intervalId);
    }, []);

    const handleClick = async () => {
        try {
            await Client.runSyncJob();
            setIsRunning(true);
        } catch (err) {
            setError('Failed to start sync job');
        }
    };

    return (
        <div className='form-group'>
            <label className='col-sm-4 control-label'>
                {'Membership Sync Job'}
            </label>
            <div className='col-sm-8'>
                <button
                    onClick={handleClick}
                    className='btn btn-primary'
                    disabled={isRunning || isLoading}
                >
                    {isLoading ? 'Loading...' : 'Run Membership Sync'}
                </button>

                {error && <div className='text-danger mt-2'>{error}</div>}

                {isRunning && (
                    <div className='text-info mt-2'>
                        <i className='fa fa-spinner fa-spin mr-2'/>
                        {' Sync job is currently running...'}
                    </div>
                )}
                <div className='help-text'>
                    {'This will synchronize all team and channel memberships with the group memberships in the system.'}
                </div>
            </div>
        </div>
    );
};

export default MembershipJobButton;
