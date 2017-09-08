/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

package org.apache.kylin.job.execution;

import static org.apache.kylin.job.constant.ExecutableConstants.MR_JOB_ID;
import static org.apache.kylin.job.constant.ExecutableConstants.YARN_APP_ID;
import static org.apache.kylin.job.constant.ExecutableConstants.YARN_APP_URL;

import java.lang.reflect.Constructor;
import java.util.HashMap;
import java.util.IllegalFormatException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.apache.commons.lang3.StringUtils;
import org.apache.kylin.common.KylinConfig;
import org.apache.kylin.common.util.ClassUtil;
import org.apache.kylin.job.constant.ExecutableConstants;
import org.apache.kylin.job.dao.ExecutableDao;
import org.apache.kylin.job.dao.ExecutableOutputPO;
import org.apache.kylin.job.dao.ExecutablePO;
import org.apache.kylin.job.exception.IllegalStateTranferException;
import org.apache.kylin.job.exception.PersistentException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Preconditions;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;

/**
 */
public class ExecutableManager {

    private static final Logger logger = LoggerFactory.getLogger(ExecutableManager.class);
    private static final ConcurrentMap<KylinConfig, ExecutableManager> CACHE = new ConcurrentHashMap<KylinConfig, ExecutableManager>();

    private final KylinConfig config;
    private final ExecutableDao executableDao;

    private ExecutableManager(KylinConfig config) {
        logger.info("Using metadata url: " + config);
        this.config = config;
        this.executableDao = ExecutableDao.getInstance(config);
    }

    public static ExecutableManager getInstance(KylinConfig config) {
        ExecutableManager r = CACHE.get(config);
        if (r == null) {
            synchronized (ExecutableManager.class) {
                r = CACHE.get(config);
                if (r == null) {
                    r = new ExecutableManager(config);
                    CACHE.put(config, r);
                    if (CACHE.size() > 1) {
                        logger.warn("More than one singleton exist");
                    }
                }
            }
        }
        return r;
    }

    public static void clearCache() {
        CACHE.clear();
    }

    public static void clearCache(KylinConfig kylinConfig) {
        if (kylinConfig != null)
            CACHE.remove(kylinConfig);
    }

    private static ExecutablePO parse(AbstractExecutable executable) {
        ExecutablePO result = new ExecutablePO();
        result.setName(executable.getName());
        result.setUuid(executable.getId());
        result.setType(executable.getClass().getName());
        result.setParams(executable.getParams());
        if (executable instanceof ChainedExecutable) {
            List<ExecutablePO> tasks = Lists.newArrayList();
            for (AbstractExecutable task : ((ChainedExecutable) executable).getTasks()) {
                tasks.add(parse(task));
            }
            result.setTasks(tasks);
        }
        if (executable instanceof CheckpointExecutable) {
            List<ExecutablePO> tasksForCheck = Lists.newArrayList();
            for (AbstractExecutable taskForCheck : ((CheckpointExecutable) executable).getSubTasksForCheck()) {
                tasksForCheck.add(parse(taskForCheck));
            }
            result.setTasksForCheck(tasksForCheck);
        }
        return result;
    }

    public void addJob(AbstractExecutable executable) {
        try {
            executable.initConfig(config);
            executableDao.addJob(parse(executable));
            addJobOutput(executable);
        } catch (PersistentException e) {
            logger.error("fail to submit job:" + executable.getId(), e);
            throw new RuntimeException(e);
        }
    }

    private void addJobOutput(AbstractExecutable executable) throws PersistentException {
        ExecutableOutputPO executableOutputPO = new ExecutableOutputPO();
        executableOutputPO.setUuid(executable.getId());
        executableDao.addJobOutput(executableOutputPO);
        if (executable instanceof DefaultChainedExecutable) {
            for (AbstractExecutable subTask : ((DefaultChainedExecutable) executable).getTasks()) {
                addJobOutput(subTask);
            }
        }
    }

    public void updateCheckpointJob(String jobId, List<AbstractExecutable> subTasksForCheck) {
        try {
            final ExecutablePO job = executableDao.getJob(jobId);
            Preconditions.checkArgument(job != null, "there is no related job for job id:" + jobId);

            List<ExecutablePO> tasksForCheck = Lists.newArrayListWithExpectedSize(subTasksForCheck.size());
            for (AbstractExecutable taskForCheck : subTasksForCheck) {
                tasksForCheck.add(parse(taskForCheck));
            }
            job.setTasksForCheck(tasksForCheck);
            executableDao.updateJob(job);
        } catch (PersistentException e) {
            logger.error("fail to update checkpoint job:" + jobId, e);
            throw new RuntimeException(e);
        }
    }

    //for ut
    public void deleteJob(String jobId) {
        try {
            executableDao.deleteJob(jobId);
        } catch (PersistentException e) {
            logger.error("fail to delete job:" + jobId, e);
            throw new RuntimeException(e);
        }
    }

    public AbstractExecutable getJob(String uuid) {
        try {
            return parseTo(executableDao.getJob(uuid));
        } catch (PersistentException e) {
            logger.error("fail to get job:" + uuid, e);
            throw new RuntimeException(e);
        }
    }

    public Output getOutput(String uuid) {
        try {
            final ExecutableOutputPO jobOutput = executableDao.getJobOutput(uuid);
            Preconditions.checkArgument(jobOutput != null, "there is no related output for job id:" + uuid);
            return parseOutput(jobOutput);
        } catch (PersistentException e) {
            logger.error("fail to get job output:" + uuid, e);
            throw new RuntimeException(e);
        }
    }

    private DefaultOutput parseOutput(ExecutableOutputPO jobOutput) {
        final DefaultOutput result = new DefaultOutput();
        result.setExtra(jobOutput.getInfo());
        result.setState(ExecutableState.valueOf(jobOutput.getStatus()));
        result.setVerboseMsg(jobOutput.getContent());
        result.setLastModified(jobOutput.getLastModified());
        return result;
    }

    public Map<String, Output> getAllOutputs() {
        try {
            final List<ExecutableOutputPO> jobOutputs = executableDao.getJobOutputs();
            HashMap<String, Output> result = Maps.newHashMap();
            for (ExecutableOutputPO jobOutput : jobOutputs) {
                result.put(jobOutput.getId(), parseOutput(jobOutput));
            }
            return result;
        } catch (PersistentException e) {
            logger.error("fail to get all job output:", e);
            throw new RuntimeException(e);
        }
    }

    public Map<String, Output> getAllOutputs(long timeStartInMillis, long timeEndInMillis) {
        try {
            final List<ExecutableOutputPO> jobOutputs = executableDao.getJobOutputs(timeStartInMillis, timeEndInMillis);
            HashMap<String, Output> result = Maps.newHashMap();
            for (ExecutableOutputPO jobOutput : jobOutputs) {
                result.put(jobOutput.getId(), parseOutput(jobOutput));
            }
            return result;
        } catch (PersistentException e) {
            logger.error("fail to get all job output:", e);
            throw new RuntimeException(e);
        }
    }

    public List<AbstractExecutable> getAllExecutables() {
        try {
            List<AbstractExecutable> ret = Lists.newArrayList();
            for (ExecutablePO po : executableDao.getJobs()) {
                try {
                    AbstractExecutable ae = parseTo(po);
                    ret.add(ae);
                } catch (IllegalArgumentException e) {
                    logger.error("error parsing one executabePO: ", e);
                }
            }
            return ret;
        } catch (PersistentException e) {
            logger.error("error get All Jobs", e);
            throw new RuntimeException(e);
        }
    }

    public List<AbstractExecutable> getAllExecutables(long timeStartInMillis, long timeEndInMillis) {
        try {
            List<AbstractExecutable> ret = Lists.newArrayList();
            for (ExecutablePO po : executableDao.getJobs(timeStartInMillis, timeEndInMillis)) {
                try {
                    AbstractExecutable ae = parseTo(po);
                    ret.add(ae);
                } catch (IllegalArgumentException e) {
                    logger.error("error parsing one executabePO: ", e);
                }
            }
            return ret;
        } catch (PersistentException e) {
            logger.error("error get All Jobs", e);
            throw new RuntimeException(e);
        }
    }

    /**
     * Since ExecutableManager will instantiate all AbstractExecutable class by Class.forName(), but for each version release,
     * new classes are introduced, old classes are deprecated, renamed or removed. The Class.forName() will throw out
     * ClassNotFoundException. This API is used to retrieve the Executable Object list, not for calling the object method,
     * so we could just instance the parent common class instead of the concrete class. It will tolerate the class missing issue.
     *
     * @param timeStartInMillis
     * @param timeEndInMillis
     * @param expectedClass
     * @return
     */
    public List<AbstractExecutable> getAllAbstractExecutables(long timeStartInMillis, long timeEndInMillis, Class<? extends AbstractExecutable> expectedClass) {
        try {
            List<AbstractExecutable> ret = Lists.newArrayList();
            for (ExecutablePO po : executableDao.getJobs(timeStartInMillis, timeEndInMillis)) {
                try {
                    AbstractExecutable ae = parseToAbstract(po, expectedClass);
                    ret.add(ae);
                } catch (IllegalArgumentException e) {
                    logger.error("error parsing one executabePO: ", e);
                }
            }
            return ret;
        } catch (PersistentException e) {
            logger.error("error get All Jobs", e);
            throw new RuntimeException(e);
        }
    }

    public AbstractExecutable getAbstractExecutable(String uuid, Class<? extends AbstractExecutable> expectedClass) {
        try {
            return parseToAbstract(executableDao.getJob(uuid), expectedClass);
        } catch (PersistentException e) {
            logger.error("fail to get job:" + uuid, e);
            throw new RuntimeException(e);
        }
    }

    public List<String> getAllJobIds() {
        try {
            return executableDao.getJobIds();
        } catch (PersistentException e) {
            logger.error("error get All Job Ids", e);
            throw new RuntimeException(e);
        }
    }

    public void updateAllRunningJobsToError() {
        try {
            final List<ExecutableOutputPO> jobOutputs = executableDao.getJobOutputs();
            for (ExecutableOutputPO executableOutputPO : jobOutputs) {
                if (executableOutputPO.getStatus().equalsIgnoreCase(ExecutableState.RUNNING.toString())) {
                    executableOutputPO.setStatus(ExecutableState.ERROR.toString());
                    executableDao.updateJobOutput(executableOutputPO);
                }
            }
        } catch (PersistentException e) {
            logger.error("error reset job status from RUNNING to ERROR", e);
            throw new RuntimeException(e);
        }
    }

    public void resumeAllRunningJobs() {
        try {
            final List<ExecutableOutputPO> jobOutputs = executableDao.getJobOutputs();
            for (ExecutableOutputPO executableOutputPO : jobOutputs) {
                if (executableOutputPO.getStatus().equalsIgnoreCase(ExecutableState.RUNNING.toString())) {
                    executableOutputPO.setStatus(ExecutableState.READY.toString());
                    executableDao.updateJobOutput(executableOutputPO);
                }
            }
        } catch (PersistentException e) {
            logger.error("error reset job status from RUNNING to READY", e);
            throw new RuntimeException(e);
        }
    }

    public void resumeRunningJobForce(String jobId) {
        AbstractExecutable job = getJob(jobId);
        if (job == null) {
            return;
        }

        if (job instanceof DefaultChainedExecutable) {
            List<AbstractExecutable> tasks = ((DefaultChainedExecutable) job).getTasks();
            for (AbstractExecutable task : tasks) {
                if (task.getStatus() == ExecutableState.RUNNING) {
                    updateJobOutput(task.getId(), ExecutableState.READY, null, null);
                    break;
                }
            }
        }
        updateJobOutput(jobId, ExecutableState.READY, null, null);
    }

    public void resumeJob(String jobId) {
        AbstractExecutable job = getJob(jobId);
        if (job == null) {
            return;
        }
        Map<String, String> info = null;
        if (job instanceof DefaultChainedExecutable) {
            List<AbstractExecutable> tasks = ((DefaultChainedExecutable) job).getTasks();
            for (AbstractExecutable task : tasks) {
                if (task.getStatus() == ExecutableState.ERROR || task.getStatus() == ExecutableState.STOPPED) {
                    updateJobOutput(task.getId(), ExecutableState.READY, null, null);
                    break;
                }
            }
            info = Maps.newHashMap();
            final long endTime = job.getEndTime();
            long interruptTime = System.currentTimeMillis() - endTime + job.getInterruptTime();
            info.putAll(getJobOutput(jobId).getInfo());
            info.put(AbstractExecutable.INTERRUPT_TIME, Long.toString(interruptTime));
            info.remove(AbstractExecutable.END_TIME);
        }
        updateJobOutput(jobId, ExecutableState.READY, info, null);
    }

    public void discardJob(String jobId) {
        AbstractExecutable job = getJob(jobId);
        if (job == null) {
            return;
        }
        if (job.getStatus().isFinalState()) {
            if (job.getStatus() != ExecutableState.DISCARDED) {
                logger.warn("The status of job " + jobId + " is " + job.getStatus().toString()
                        + ". It's final state and cannot be transfer to be discarded!!!");
            } else {
                logger.warn("The job " + jobId + " has been discarded.");
            }
            return;
        }
        if (job instanceof DefaultChainedExecutable) {
            List<AbstractExecutable> tasks = ((DefaultChainedExecutable) job).getTasks();
            for (AbstractExecutable task : tasks) {
                if (!task.getStatus().isFinalState()) {
                    updateJobOutput(task.getId(), ExecutableState.DISCARDED, null, null);
                }
            }
        }
        updateJobOutput(jobId, ExecutableState.DISCARDED, null, null);
    }

    public void rollbackJob(String jobId, String stepId) {
        AbstractExecutable job = getJob(jobId);
        if (job == null) {
            return;
        }

        if (job instanceof DefaultChainedExecutable) {
            List<AbstractExecutable> tasks = ((DefaultChainedExecutable) job).getTasks();
            for (AbstractExecutable task : tasks) {
                if (task.getId().compareTo(stepId) >= 0) {
                    logger.debug("rollback task : " + task);
                    updateJobOutput(task.getId(), ExecutableState.READY, Maps.<String, String> newHashMap(), "");
                }
            }
        }

        if (job.getStatus() == ExecutableState.SUCCEED) {
            updateJobOutput(job.getId(), ExecutableState.READY, null, null);
        }
    }

    public void pauseJob(String jobId) {
        AbstractExecutable job = getJob(jobId);
        if (job == null) {
            return;
        }

        updateJobOutput(jobId, ExecutableState.STOPPED, null, null);
    }

    public ExecutableOutputPO getJobOutput(String jobId) {
        try {
            return executableDao.getJobOutput(jobId);
        } catch (PersistentException e) {
            logger.error("Can't get output of Job " + jobId);
            throw new RuntimeException(e);
        }
    }

    public void updateJobOutput(String jobId, ExecutableState newStatus, Map<String, String> info, String output) {
        try {
            final ExecutableOutputPO jobOutput = executableDao.getJobOutput(jobId);
            Preconditions.checkArgument(jobOutput != null, "there is no related output for job id:" + jobId);
            ExecutableState oldStatus = ExecutableState.valueOf(jobOutput.getStatus());
            if (newStatus != null && oldStatus != newStatus) {
                if (!ExecutableState.isValidStateTransfer(oldStatus, newStatus)) {
                    throw new IllegalStateTranferException("there is no valid state transfer from:" + oldStatus + " to:" + newStatus + ", job id: " + jobId);
                }
                jobOutput.setStatus(newStatus.toString());
            }
            if (info != null) {
                jobOutput.setInfo(info);
            }
            if (output != null) {
                jobOutput.setContent(output);
            }
            executableDao.updateJobOutput(jobOutput);
            logger.info("job id:" + jobId + " from " + oldStatus + " to " + newStatus);
        } catch (PersistentException e) {
            logger.error("error change job:" + jobId + " to " + newStatus);
            throw new RuntimeException(e);
        }
    }

    //for migration only
    //TODO delete when migration finished
    public void resetJobOutput(String jobId, ExecutableState state, String output) {
        try {
            final ExecutableOutputPO jobOutput = executableDao.getJobOutput(jobId);
            jobOutput.setStatus(state.toString());
            if (output != null) {
                jobOutput.setContent(output);
            }
            executableDao.updateJobOutput(jobOutput);
        } catch (PersistentException e) {
            throw new RuntimeException(e);
        }
    }

    public void addJobInfo(String id, Map<String, String> info) {
        if (info == null) {
            return;
        }

        // post process
        if (info.containsKey(MR_JOB_ID) && !info.containsKey(ExecutableConstants.YARN_APP_ID)) {
            String jobId = info.get(MR_JOB_ID);
            if (jobId.startsWith("job_")) {
                info.put(YARN_APP_ID, jobId.replace("job_", "application_"));
            }
        }

        if (info.containsKey(YARN_APP_ID) && !StringUtils.isEmpty(config.getJobTrackingURLPattern())) {
            String pattern = config.getJobTrackingURLPattern();
            try {
                String newTrackingURL = String.format(pattern, info.get(YARN_APP_ID));
                info.put(YARN_APP_URL, newTrackingURL);
            } catch (IllegalFormatException ife) {
                logger.error("Illegal tracking url pattern: " + config.getJobTrackingURLPattern());
            }
        }

        try {
            ExecutableOutputPO output = executableDao.getJobOutput(id);
            Preconditions.checkArgument(output != null, "there is no related output for job id:" + id);
            output.getInfo().putAll(info);
            executableDao.updateJobOutput(output);
        } catch (PersistentException e) {
            logger.error("error update job info, id:" + id + "  info:" + info.toString());
            throw new RuntimeException(e);
        }
    }

    public void addJobInfo(String id, String key, String value) {
        Map<String, String> info = Maps.newHashMap();
        info.put(key, value);
        addJobInfo(id, info);
    }

    private AbstractExecutable parseTo(ExecutablePO executablePO) {
        if (executablePO == null) {
            logger.warn("executablePO is null");
            return null;
        }
        String type = executablePO.getType();
        try {
            Class<? extends AbstractExecutable> clazz = ClassUtil.forName(type, AbstractExecutable.class);
            Constructor<? extends AbstractExecutable> constructor = clazz.getConstructor();
            AbstractExecutable result = constructor.newInstance();
            result.initConfig(config);
            result.setId(executablePO.getUuid());
            result.setName(executablePO.getName());
            result.setParams(executablePO.getParams());
            List<ExecutablePO> tasks = executablePO.getTasks();
            if (tasks != null && !tasks.isEmpty()) {
                Preconditions.checkArgument(result instanceof ChainedExecutable);
                for (ExecutablePO subTask : tasks) {
                    ((ChainedExecutable) result).addTask(parseTo(subTask));
                }
            }
            List<ExecutablePO> tasksForCheck = executablePO.getTasksForCheck();
            if (tasksForCheck != null && !tasksForCheck.isEmpty()) {
                Preconditions.checkArgument(result instanceof CheckpointExecutable);
                for (ExecutablePO subTaskForCheck : tasksForCheck) {
                    ((CheckpointExecutable) result).addTaskForCheck(parseTo(subTaskForCheck));
                }
            }
            return result;
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("cannot parse this job:" + executablePO.getId(), e);
        }
    }

    private AbstractExecutable parseToAbstract(ExecutablePO executablePO, Class<? extends AbstractExecutable> expectedClass) {
        if (executablePO == null) {
            logger.warn("executablePO is null");
            return null;
        }
        String type = executablePO.getType();
        try {
            Class<? extends AbstractExecutable> clazz = null;
            try {
                clazz = ClassUtil.forName(type, AbstractExecutable.class);
            } catch (ClassNotFoundException e) {
                clazz = ClassUtil.forName(expectedClass.getName(), AbstractExecutable.class);
            }
            Constructor<? extends AbstractExecutable> constructor = clazz.getConstructor();
            AbstractExecutable result = constructor.newInstance();
            result.initConfig(config);
            result.setId(executablePO.getUuid());
            result.setName(executablePO.getName());
            result.setParams(executablePO.getParams());
            List<ExecutablePO> tasks = executablePO.getTasks();
            if (tasks != null && !tasks.isEmpty()) {
                Preconditions.checkArgument(result instanceof ChainedExecutable);
                for (ExecutablePO subTask : tasks) {
                    AbstractExecutable parseToTask = null;
                    try {
                        parseToTask = parseTo(subTask);
                    } catch (IllegalStateException e) {
                        parseToTask = parseToAbstract(subTask, DefaultChainedExecutable.class);
                    }
                    ((ChainedExecutable) result).addTask(parseToTask);
                }
            }
            return result;
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("cannot parse this job:" + executablePO.getId(), e);
        }
    }
}
